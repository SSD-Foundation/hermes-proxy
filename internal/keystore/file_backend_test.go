package keystore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestDeriveMasterKeyDeterministic(t *testing.T) {
	salt := []byte("1234567890abcdef")
	key1 := deriveMasterKey("password", salt)
	key2 := deriveMasterKey("password", salt)
	if string(key1) != string(key2) {
		t.Fatal("expected deterministic key derivation")
	}

	key3 := deriveMasterKey("different", salt)
	if string(key1) == string(key3) {
		t.Fatal("expected different passphrase to yield different key")
	}
}

func TestInitializeUnlockAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)
	backend.MarkNonChatSecretIDs("mesh_identity")

	ctx := context.Background()
	if err := backend.Initialize(ctx, "topsecret"); err != nil {
		t.Fatalf("initialize keystore: %v", err)
	}

	if err := backend.StoreSecret(ctx, "mesh_identity", []byte("identity-bytes")); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	chat := ChatSecretRecord{
		ChatID:         "chat-1",
		KeyVersion:     3,
		LocalKeyID:     "local-key",
		RemoteKeyID:    "remote-key",
		LocalPublic:    bytes32(0x01),
		RemotePublic:   bytes32(0x02),
		LocalPrivate:   bytes32(0x03),
		HKDFSalt:       []byte("salt"),
		HKDFInfo:       []byte("info"),
		SendKey:        bytes32(0x04),
		RecvKey:        bytes32(0x05),
		MACKey:         bytes32(0x06),
		RatchetSeed:    bytes32(0x07),
		CreatedAt:      time.Now().UTC().Add(-time.Minute),
		RotatedAt:      time.Now().UTC(),
		LegacyCombined: nil,
	}
	if err := backend.StoreChatSecret(ctx, chat); err != nil {
		t.Fatalf("store chat secret: %v", err)
	}

	backend2 := NewFileBackend(path)
	backend2.MarkNonChatSecretIDs("mesh_identity")
	if err := backend2.Unlock(ctx, "topsecret"); err != nil {
		t.Fatalf("unlock keystore: %v", err)
	}

	loaded, err := backend2.LoadSecret(ctx, "mesh_identity")
	if err != nil {
		t.Fatalf("load secret: %v", err)
	}
	if string(loaded) != "identity-bytes" {
		t.Fatalf("expected secret round-trip, got %s", string(loaded))
	}

	loadedChat, err := backend2.LoadChatSecret(ctx, "chat-1")
	if err != nil {
		t.Fatalf("load chat secret: %v", err)
	}
	if loadedChat.KeyVersion != 3 || loadedChat.LocalKeyID != "local-key" || loadedChat.RemoteKeyID != "remote-key" {
		t.Fatalf("unexpected chat metadata: %+v", loadedChat)
	}
	if len(loadedChat.LocalPublic) != x25519KeySize || len(loadedChat.RemotePublic) != x25519KeySize {
		t.Fatalf("expected pubkey sizes preserved, got %d/%d", len(loadedChat.LocalPublic), len(loadedChat.RemotePublic))
	}
}

func TestUnlockWithWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)

	ctx := context.Background()
	if err := backend.Initialize(ctx, "correct"); err != nil {
		t.Fatalf("initialize keystore: %v", err)
	}

	backend2 := NewFileBackend(path)
	if err := backend2.Unlock(ctx, "wrong"); err == nil {
		t.Fatal("expected unlock failure with wrong passphrase")
	} else if !errors.Is(err, ErrInvalidPass) {
		t.Fatalf("expected ErrInvalidPass, got %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)

	ctx := context.Background()
	if err := backend.Initialize(ctx, "correct"); err != nil {
		t.Fatalf("initialize keystore: %v", err)
	}
	if err := backend.StoreChatSecret(ctx, ChatSecretRecord{
		ChatID:         "chat-1",
		KeyVersion:     1,
		LegacyCombined: []byte("secret"),
	}); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read keystore: %v", err)
	}

	var file keystoreFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode keystore file: %v", err)
	}

	ct, err := base64.StdEncoding.DecodeString(file.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	ct[0] ^= 0xFF // flip a bit to simulate tampering
	file.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	mutated, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode mutated keystore: %v", err)
	}
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatalf("write tampered keystore: %v", err)
	}

	backend2 := NewFileBackend(path)
	if err := backend2.Unlock(ctx, "correct"); !errors.Is(err, ErrInvalidPass) {
		t.Fatalf("expected ErrInvalidPass after tamper, got %v", err)
	}
}

func TestChatSecretZeroizationOnUpdateAndDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)

	ctx := context.Background()
	if err := backend.Initialize(ctx, "pass"); err != nil {
		t.Fatalf("initialize keystore: %v", err)
	}

	first := ChatSecretRecord{
		ChatID:         "chat-1",
		KeyVersion:     1,
		LocalPublic:    bytes32(0xAA),
		LegacyCombined: []byte("legacy"),
	}
	if err := backend.StoreChatSecret(ctx, first); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	original := backend.chatSecrets["chat-1"]

	second := ChatSecretRecord{
		ChatID:       "chat-1",
		KeyVersion:   2,
		RemotePublic: bytes32(0xBB),
	}
	if err := backend.StoreChatSecret(ctx, second); err != nil {
		t.Fatalf("store secret second time: %v", err)
	}
	latest := backend.chatSecrets["chat-1"]
	for i, b := range original.LocalPublic {
		if b != 0 {
			t.Fatalf("expected original public key zeroed at byte %d (got %d)", i, b)
		}
	}
	for i, b := range original.LegacyCombined {
		if b != 0 {
			t.Fatalf("expected legacy blob zeroed at byte %d (got %d)", i, b)
		}
	}

	if err := backend.DeleteChatSecret(ctx, "chat-1"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	for i, b := range latest.RemotePublic {
		if b != 0 {
			t.Fatalf("expected stored secret zeroed at delete at byte %d (got %d)", i, b)
		}
	}
}

func TestLegacyMigrationFromVersionOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")

	secrets := map[string][]byte{
		"mesh_identity": []byte("identity"),
		"chat-legacy":   []byte("combined-legacy"),
	}
	writeLegacyKeystore(t, path, "pass", secrets)

	backend := NewFileBackend(path)
	backend.MarkNonChatSecretIDs("mesh_identity")
	if err := backend.Unlock(context.Background(), "pass"); err != nil {
		t.Fatalf("unlock legacy keystore: %v", err)
	}

	ids, err := backend.ListChatSecrets(context.Background())
	if err != nil {
		t.Fatalf("list chat secrets: %v", err)
	}
	if len(ids) != 1 || ids[0] != "chat-legacy" {
		t.Fatalf("expected legacy chat id listed, got %v", ids)
	}

	chat, err := backend.LoadChatSecret(context.Background(), "chat-legacy")
	if err != nil {
		t.Fatalf("load legacy chat secret: %v", err)
	}
	if string(chat.LegacyCombined) != "combined-legacy" {
		t.Fatalf("expected legacy blob preserved, got %s", string(chat.LegacyCombined))
	}
	if _, exists := backend.secrets["chat-legacy"]; exists {
		t.Fatalf("expected legacy entry removed from generic secrets after migration")
	}

	file := readKeystoreFile(t, path)
	if file.Version != currentVersion {
		t.Fatalf("expected migrated file to use version %d, got %d", currentVersion, file.Version)
	}
}

func TestCorruptedPayloadFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")

	badChat := ChatSecretRecord{
		ChatID:      "chat-bad",
		KeyVersion:  1,
		LocalPublic: []byte{1, 2, 3}, // invalid length
	}
	payload := sealedPayload{
		Secrets: map[string][]byte{
			"mesh_identity": []byte("id"),
		},
		ChatSecrets: map[string]ChatSecretRecord{
			"chat-bad": badChat,
		},
	}

	master := deriveMasterKey("pass", []byte("0123456789abcdef"))
	nonce, ciphertext, err := sealPayload(master, payload)
	if err != nil {
		t.Fatalf("seal payload: %v", err)
	}
	file := keystoreFile{
		Version:    currentVersion,
		Salt:       base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	serialized, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatalf("marshal file: %v", err)
	}
	if err := os.WriteFile(path, serialized, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	backend := NewFileBackend(path)
	if err := backend.Unlock(context.Background(), "pass"); !errors.Is(err, ErrInvalidChatSecret) {
		t.Fatalf("expected invalid chat secret error, got %v", err)
	}
}

func TestSecretSizeLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)
	ctx := context.Background()
	if err := backend.Initialize(ctx, "pass"); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	huge := make([]byte, maxSecretBytes+1)
	if err := backend.StoreSecret(ctx, "too-big", huge); !errors.Is(err, ErrSecretTooBig) {
		t.Fatalf("expected ErrSecretTooBig, got %v", err)
	}

	bigChat := make([]byte, maxChatSecretBytes+1)
	err := backend.StoreChatSecret(ctx, ChatSecretRecord{
		ChatID:         "big-chat",
		KeyVersion:     1,
		LegacyCombined: bigChat,
	})
	if !errors.Is(err, ErrChatSecretTooBig) {
		t.Fatalf("expected ErrChatSecretTooBig, got %v", err)
	}
}

func TestOperationsRequireUnlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)

	if err := backend.StoreSecret(context.Background(), "id", []byte("secret")); !errors.Is(err, ErrLocked) {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestInitializeFailsWhenFileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backend := NewFileBackend(path)
	if err := backend.Initialize(context.Background(), "pass"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func bytes32(val byte) []byte {
	out := make([]byte, x25519KeySize)
	for i := range out {
		out[i] = val
	}
	return out
}

func writeLegacyKeystore(t *testing.T, path, passphrase string, secrets map[string][]byte) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	master := deriveMasterKey(passphrase, salt)

	payload := make(map[string]string, len(secrets))
	for k, v := range secrets {
		payload[k] = base64.StdEncoding.EncodeToString(v)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	aead, err := chacha20poly1305.NewX(master)
	if err != nil {
		t.Fatalf("init cipher: %v", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	file := keystoreFile{
		Version:    1,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	serialized, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatalf("marshal keystore: %v", err)
	}
	if err := os.WriteFile(path, serialized, 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
}

func readKeystoreFile(t *testing.T, path string) keystoreFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var file keystoreFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode file: %v", err)
	}
	return file
}
