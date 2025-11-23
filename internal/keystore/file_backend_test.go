package keystore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
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

	ctx := context.Background()
	if err := backend.Initialize(ctx, "topsecret"); err != nil {
		t.Fatalf("initialize keystore: %v", err)
	}

	// store a secret to confirm persistence
	if err := backend.StoreSecret(ctx, "node_identity", []byte("identity-bytes")); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	// create a fresh backend and unlock
	backend2 := NewFileBackend(path)
	if err := backend2.Unlock(ctx, "topsecret"); err != nil {
		t.Fatalf("unlock keystore: %v", err)
	}

	loaded, err := backend2.LoadSecret(ctx, "node_identity")
	if err != nil {
		t.Fatalf("load secret: %v", err)
	}
	if string(loaded) != "identity-bytes" {
		t.Fatalf("expected secret round-trip, got %s", string(loaded))
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
	if err := backend.StoreSecret(ctx, "chat-1", []byte("secret")); err != nil {
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

func TestSecretZeroizationOnUpdateAndDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.json")
	backend := NewFileBackend(path)

	ctx := context.Background()
	if err := backend.Initialize(ctx, "pass"); err != nil {
		t.Fatalf("initialize keystore: %v", err)
	}

	if err := backend.StoreSecret(ctx, "chat-1", []byte("old-value")); err != nil {
		t.Fatalf("store secret: %v", err)
	}
	original := backend.secrets["chat-1"]

	if err := backend.StoreSecret(ctx, "chat-1", []byte("new-value")); err != nil {
		t.Fatalf("store secret second time: %v", err)
	}
	latest := backend.secrets["chat-1"]
	for i, b := range original {
		if b != 0 {
			t.Fatalf("expected original secret zeroed at byte %d (got %d)", i, b)
		}
	}

	if err := backend.DeleteSecret(ctx, "chat-1"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	for i, b := range latest {
		if b != 0 {
			t.Fatalf("expected stored secret zeroed at delete at byte %d (got %d)", i, b)
		}
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
