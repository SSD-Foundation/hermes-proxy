package keystore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// KeyBackend exposes the keystore contract used by the server.
type KeyBackend interface {
	Initialize(ctx context.Context, passphrase string) error
	Unlock(ctx context.Context, passphrase string) error
	StoreSecret(ctx context.Context, keyID string, secret []byte) error
	LoadSecret(ctx context.Context, keyID string) ([]byte, error)
	DeleteSecret(ctx context.Context, keyID string) error
}

// FileBackend is a placeholder file-based keystore with Argon2id master key derivation.
type FileBackend struct {
	path      string
	salt      []byte
	masterKey []byte
	secrets   map[string][]byte
	mu        sync.RWMutex
}

const (
	currentVersion = 1
	argonTime      = 1
	argonMemory    = 64 * 1024
	argonThreads   = 4
	argonKeyLength = 32
	nonceSize      = chacha20poly1305.NonceSizeX
)

var (
	ErrLocked          = errors.New("keystore is locked")
	ErrAlreadyExists   = errors.New("keystore already exists")
	ErrNotInitialized  = errors.New("keystore not initialized")
	ErrInvalidSecretID = errors.New("secret id is required")
	ErrInvalidPass     = errors.New("invalid passphrase")
)

type keystoreFile struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// NewFileBackend constructs a keystore backed by the provided file path.
func NewFileBackend(path string) *FileBackend {
	return &FileBackend{
		path:    path,
		secrets: make(map[string][]byte),
	}
}

// Path returns the backing file path (primarily for logging and tests).
func (b *FileBackend) Path() string {
	return b.path
}

// Initialize creates the keystore file if it does not already exist.
func (b *FileBackend) Initialize(ctx context.Context, passphrase string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if passphrase == "" {
		return fmt.Errorf("passphrase required: %w", ErrInvalidPass)
	}

	if _, err := os.Stat(b.path); err == nil {
		return ErrAlreadyExists
	}

	if err := os.MkdirAll(filepath.Dir(b.path), 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create keystore directory: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	zeroSecretMap(b.secrets)
	b.salt = salt
	zeroBytes(b.masterKey)
	b.masterKey = deriveMasterKey(passphrase, salt)
	b.secrets = make(map[string][]byte)

	if err := b.persist(); err != nil {
		return fmt.Errorf("persist keystore: %w", err)
	}

	return ctx.Err()
}

// Unlock loads the keystore file and derives the master key.
func (b *FileBackend) Unlock(ctx context.Context, passphrase string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	raw, err := os.ReadFile(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotInitialized
		}
		return fmt.Errorf("read keystore: %w", err)
	}

	var file keystoreFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("decode keystore: %w", err)
	}
	if file.Version != currentVersion {
		return fmt.Errorf("unsupported keystore version %d", file.Version)
	}

	salt, err := base64.StdEncoding.DecodeString(file.Salt)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(file.Nonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(file.Ciphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}

	master := deriveMasterKey(passphrase, salt)
	secrets, err := openSecrets(master, nonce, ciphertext)
	if err != nil {
		zeroBytes(master)
		return err
	}

	zeroSecretMap(b.secrets)
	zeroBytes(b.masterKey)
	b.masterKey = master
	b.salt = salt
	b.secrets = secrets

	return ctx.Err()
}

// StoreSecret writes or overwrites a secret and persists the file.
func (b *FileBackend) StoreSecret(ctx context.Context, keyID string, secret []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.ensureUnlocked(); err != nil {
		return err
	}
	if keyID == "" {
		return ErrInvalidSecretID
	}

	if existing, ok := b.secrets[keyID]; ok {
		zeroBytes(existing)
	}
	b.secrets[keyID] = append([]byte(nil), secret...)
	if err := b.persist(); err != nil {
		return fmt.Errorf("persist secret: %w", err)
	}
	return ctx.Err()
}

// LoadSecret fetches a secret by ID.
func (b *FileBackend) LoadSecret(ctx context.Context, keyID string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.ensureUnlocked(); err != nil {
		return nil, err
	}
	secret, ok := b.secrets[keyID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), secret...), ctx.Err()
}

// DeleteSecret removes a secret by ID and persists the change.
func (b *FileBackend) DeleteSecret(ctx context.Context, keyID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.ensureUnlocked(); err != nil {
		return err
	}
	if existing, ok := b.secrets[keyID]; ok {
		zeroBytes(existing)
		delete(b.secrets, keyID)
	}
	if err := b.persist(); err != nil {
		return fmt.Errorf("persist keystore after delete: %w", err)
	}
	return ctx.Err()
}

func (b *FileBackend) ensureUnlocked() error {
	if len(b.masterKey) == 0 || len(b.salt) == 0 {
		return ErrLocked
	}
	return nil
}

func (b *FileBackend) persist() error {
	if err := b.ensureUnlocked(); err != nil {
		return err
	}

	nonce, ciphertext, err := sealSecrets(b.masterKey, b.secrets)
	if err != nil {
		return err
	}

	payload := keystoreFile{
		Version:    currentVersion,
		Salt:       base64.StdEncoding.EncodeToString(b.salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	serialized, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode keystore: %w", err)
	}

	return os.WriteFile(b.path, serialized, 0o600)
}

func deriveMasterKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLength)
}

func sealSecrets(masterKey []byte, secrets map[string][]byte) ([]byte, []byte, error) {
	if len(masterKey) == 0 {
		return nil, nil, ErrLocked
	}

	if secrets == nil {
		secrets = make(map[string][]byte)
	}

	payload := make(map[string]string, len(secrets))
	for k, v := range secrets {
		payload[k] = base64.StdEncoding.EncodeToString(v)
	}

	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal secrets: %w", err)
	}

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("init cipher: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, serialized, nil)
	zeroBytes(serialized)

	return nonce, ciphertext, nil
}

func openSecrets(masterKey, nonce, ciphertext []byte) (map[string][]byte, error) {
	if len(masterKey) == 0 {
		return nil, ErrLocked
	}
	if len(ciphertext) == 0 {
		return map[string][]byte{}, nil
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("invalid nonce size: %w", ErrInvalidPass)
	}

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, fmt.Errorf("init cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets: %w", ErrInvalidPass)
	}
	defer zeroBytes(plaintext)

	var encoded map[string]string
	if err := json.Unmarshal(plaintext, &encoded); err != nil {
		return nil, fmt.Errorf("unmarshal secrets: %w", ErrInvalidPass)
	}

	out := make(map[string][]byte, len(encoded))
	for k, v := range encoded {
		data, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("decode secret %s: %w", k, ErrInvalidPass)
		}
		out[k] = data
	}

	return out, nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func zeroSecretMap(m map[string][]byte) {
	for k, v := range m {
		zeroBytes(v)
		delete(m, k)
	}
}
