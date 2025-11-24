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
	"sort"
	"sync"
	"time"

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
	StoreChatSecret(ctx context.Context, record ChatSecretRecord) error
	LoadChatSecret(ctx context.Context, chatID string) (ChatSecretRecord, error)
	DeleteChatSecret(ctx context.Context, chatID string) error
	ListChatSecrets(ctx context.Context) ([]string, error)
}

// FileBackend is a file-based keystore with Argon2id master key derivation and sealed chat-secret records.
type FileBackend struct {
	path           string
	salt           []byte
	masterKey      []byte
	secrets        map[string][]byte
	chatSecrets    map[string]ChatSecretRecord
	nonChatSecrets map[string]struct{}
	mu             sync.RWMutex
}

const (
	currentVersion = 2
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
	ErrInvalidSecret   = errors.New("invalid secret")
	ErrSecretTooBig    = errors.New("secret exceeds size limit")
	ErrInvalidPass     = errors.New("invalid passphrase")
	ErrCorruptFile     = errors.New("corrupted keystore")
)

type keystoreFile struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type sealedPayload struct {
	Secrets     map[string][]byte           `json:"secrets,omitempty"`
	ChatSecrets map[string]ChatSecretRecord `json:"chat_secrets,omitempty"`
}

var defaultNonChatSecretIDs = []string{"mesh_identity"}

// NewFileBackend constructs a keystore backed by the provided file path.
func NewFileBackend(path string) *FileBackend {
	nonChat := make(map[string]struct{}, len(defaultNonChatSecretIDs))
	for _, id := range defaultNonChatSecretIDs {
		nonChat[id] = struct{}{}
	}
	return &FileBackend{
		path:           path,
		secrets:        make(map[string][]byte),
		chatSecrets:    make(map[string]ChatSecretRecord),
		nonChatSecrets: nonChat,
	}
}

// Path returns the backing file path (primarily for logging and tests).
func (b *FileBackend) Path() string {
	return b.path
}

// MarkNonChatSecretIDs registers secret IDs that should never be treated as chat records during migrations or listing.
func (b *FileBackend) MarkNonChatSecretIDs(ids ...string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range ids {
		if id == "" {
			continue
		}
		b.nonChatSecrets[id] = struct{}{}
	}
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
	zeroChatSecretMap(b.chatSecrets)
	b.salt = salt
	zeroBytes(b.masterKey)
	b.masterKey = deriveMasterKey(passphrase, salt)
	b.secrets = make(map[string][]byte)
	b.chatSecrets = make(map[string]ChatSecretRecord)

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
	if file.Version != 1 && file.Version != currentVersion {
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
	secrets, chats, err := openPayload(master, nonce, ciphertext, file.Version)
	if err != nil {
		zeroBytes(master)
		return err
	}

	zeroSecretMap(b.secrets)
	zeroChatSecretMap(b.chatSecrets)
	zeroBytes(b.masterKey)
	b.masterKey = master
	b.salt = salt
	b.secrets = secrets
	b.chatSecrets = chats

	migrated := false
	if file.Version == 1 {
		migrated = b.migrateLegacyChats(time.Now())
	}
	if migrated || file.Version != currentVersion {
		if err := b.persist(); err != nil {
			return fmt.Errorf("persist migrated keystore: %w", err)
		}
	}

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
	if len(secret) == 0 {
		return fmt.Errorf("secret cannot be empty: %w", ErrInvalidSecret)
	}
	if len(secret) > maxSecretBytes {
		return fmt.Errorf("secret for %s exceeds %d bytes: %w", keyID, maxSecretBytes, ErrSecretTooBig)
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

// StoreChatSecret writes a chat secret record and persists the file.
func (b *FileBackend) StoreChatSecret(ctx context.Context, record ChatSecretRecord) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.ensureUnlocked(); err != nil {
		return err
	}

	normalized, err := normalizeChatSecret(record, time.Now())
	if err != nil {
		return err
	}

	if existing, ok := b.chatSecrets[normalized.ChatID]; ok {
		existing.Zero()
	}
	if legacy, ok := b.secrets[normalized.ChatID]; ok {
		zeroBytes(legacy)
		delete(b.secrets, normalized.ChatID)
	}

	b.chatSecrets[normalized.ChatID] = normalized.Clone()
	if err := b.persist(); err != nil {
		return fmt.Errorf("persist chat secret: %w", err)
	}
	return ctx.Err()
}

// LoadChatSecret fetches a chat secret by chat ID, falling back to legacy blobs when present.
func (b *FileBackend) LoadChatSecret(ctx context.Context, chatID string) (ChatSecretRecord, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.ensureUnlocked(); err != nil {
		return ChatSecretRecord{}, err
	}
	if chatID == "" {
		return ChatSecretRecord{}, ErrInvalidSecretID
	}

	if rec, ok := b.chatSecrets[chatID]; ok {
		return rec.Clone(), ctx.Err()
	}
	if legacy, ok := b.secrets[chatID]; ok {
		return ChatSecretRecord{
			Version:        chatSecretVersion,
			ChatID:         chatID,
			KeyVersion:     1,
			LegacyCombined: append([]byte(nil), legacy...),
		}, ctx.Err()
	}
	return ChatSecretRecord{}, os.ErrNotExist
}

// DeleteChatSecret removes a chat secret record and persists the change.
func (b *FileBackend) DeleteChatSecret(ctx context.Context, chatID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.ensureUnlocked(); err != nil {
		return err
	}
	if rec, ok := b.chatSecrets[chatID]; ok {
		rec.Zero()
		delete(b.chatSecrets, chatID)
	}
	if legacy, ok := b.secrets[chatID]; ok {
		zeroBytes(legacy)
		delete(b.secrets, chatID)
	}

	if err := b.persist(); err != nil {
		return fmt.Errorf("persist keystore after delete: %w", err)
	}
	return ctx.Err()
}

// ListChatSecrets returns sorted chat IDs, including legacy blobs not marked as non-chat secrets.
func (b *FileBackend) ListChatSecrets(ctx context.Context) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := b.ensureUnlocked(); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(b.chatSecrets))
	for id := range b.chatSecrets {
		seen[id] = struct{}{}
	}
	for id := range b.secrets {
		if _, skip := b.nonChatSecrets[id]; skip {
			continue
		}
		seen[id] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, ctx.Err()
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

	nonce, ciphertext, err := sealPayload(b.masterKey, sealedPayload{
		Secrets:     b.secrets,
		ChatSecrets: b.chatSecrets,
	})
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

func sealPayload(masterKey []byte, payload sealedPayload) ([]byte, []byte, error) {
	if len(masterKey) == 0 {
		return nil, nil, ErrLocked
	}
	if payload.Secrets == nil {
		payload.Secrets = make(map[string][]byte)
	}
	if payload.ChatSecrets == nil {
		payload.ChatSecrets = make(map[string]ChatSecretRecord)
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

func openPayload(masterKey, nonce, ciphertext []byte, version int) (map[string][]byte, map[string]ChatSecretRecord, error) {
	if len(masterKey) == 0 {
		return nil, nil, ErrLocked
	}
	if len(ciphertext) == 0 {
		return map[string][]byte{}, map[string]ChatSecretRecord{}, nil
	}
	if len(nonce) != nonceSize {
		return nil, nil, fmt.Errorf("invalid nonce size: %w", ErrInvalidPass)
	}

	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("init cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt secrets: %w", ErrInvalidPass)
	}
	defer zeroBytes(plaintext)

	switch version {
	case 1:
		var encoded map[string]string
		if err := json.Unmarshal(plaintext, &encoded); err != nil {
			return nil, nil, fmt.Errorf("unmarshal secrets: %w", ErrCorruptFile)
		}
		out := make(map[string][]byte, len(encoded))
		for k, v := range encoded {
			data, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return nil, nil, fmt.Errorf("decode secret %s: %w", k, ErrCorruptFile)
			}
			out[k] = data
		}
		return out, map[string]ChatSecretRecord{}, nil
	case currentVersion:
		var payload sealedPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return nil, nil, fmt.Errorf("unmarshal secrets: %w", ErrCorruptFile)
		}
		if payload.Secrets == nil {
			payload.Secrets = make(map[string][]byte)
		}
		if payload.ChatSecrets == nil {
			payload.ChatSecrets = make(map[string]ChatSecretRecord)
		}

		for id, rec := range payload.ChatSecrets {
			normalized, err := normalizeChatSecret(rec, rec.CreatedAt)
			if err != nil {
				return nil, nil, fmt.Errorf("chat secret %s invalid: %w", id, err)
			}
			payload.ChatSecrets[id] = normalized
		}

		return payload.Secrets, payload.ChatSecrets, nil
	default:
		return nil, nil, fmt.Errorf("unsupported keystore version %d", version)
	}
}

func (b *FileBackend) migrateLegacyChats(now time.Time) bool {
	migrated := false
	for id, data := range b.secrets {
		if _, skip := b.nonChatSecrets[id]; skip {
			continue
		}
		if _, exists := b.chatSecrets[id]; exists {
			continue
		}
		b.chatSecrets[id] = ChatSecretRecord{
			Version:        chatSecretVersion,
			ChatID:         id,
			KeyVersion:     1,
			LegacyCombined: append([]byte(nil), data...),
			CreatedAt:      now.UTC(),
		}
		zeroBytes(data)
		delete(b.secrets, id)
		migrated = true
	}
	return migrated
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

func zeroChatSecretMap(m map[string]ChatSecretRecord) {
	for k, v := range m {
		v.Zero()
		delete(m, k)
	}
}
