package keystore

import (
	"context"
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
