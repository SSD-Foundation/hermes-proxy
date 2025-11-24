package pfs

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"
)

func TestGenerateKeyPairDeterministic(t *testing.T) {
	reader := bytes.NewReader(bytes.Repeat([]byte{0x11}, 64))
	kp, err := GenerateKeyPair(reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	pubHex := hex.EncodeToString(kp.Public)
	privHex := hex.EncodeToString(kp.Private)
	if pubHex != "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13" {
		t.Fatalf("unexpected public key: %s", pubHex)
	}
	if privHex != "1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("unexpected private key: %s", privHex)
	}
	expectedID, _ := KeyIdentifier(kp.Public)
	if kp.ID != expectedID {
		t.Fatalf("expected key id %s, got %s", expectedID, kp.ID)
	}
}

func TestValidatePublicKeyRejectsInvalid(t *testing.T) {
	if err := ValidatePublicKey([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short key")
	}
	zero := make([]byte, KeySize)
	if err := ValidatePublicKey(zero); err == nil {
		t.Fatal("expected error for low-entropy key")
	}
}

func TestSharedSecretSymmetric(t *testing.T) {
	alice, err := GenerateKeyPair(bytes.NewReader(bytes.Repeat([]byte{0xAA}, 64)))
	if err != nil {
		t.Fatalf("alice keypair: %v", err)
	}
	bob, err := GenerateKeyPair(bytes.NewReader(bytes.Repeat([]byte{0xBB}, 64)))
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}

	secret1, err := SharedSecret(alice.Private, bob.Public)
	if err != nil {
		t.Fatalf("shared secret 1: %v", err)
	}
	secret2, err := SharedSecret(bob.Private, alice.Public)
	if err != nil {
		t.Fatalf("shared secret 2: %v", err)
	}
	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("shared secrets differ: %x vs %x", secret1, secret2)
	}
	if len(secret1) != KeySize {
		t.Fatalf("expected shared secret length %d, got %d", KeySize, len(secret1))
	}
}

func TestDeriveSessionKeysDeterministic(t *testing.T) {
	shared := []byte("this-is-a-shared-secret-32-bytes-len!!")
	salt := []byte("salty")
	info := []byte("hermes")

	keys, err := DeriveSessionKeys(shared, salt, info, crypto.SHA256, SessionKeySizes{})
	if err != nil {
		t.Fatalf("derive session keys: %v", err)
	}

	assertHex := func(name, expected string, actual []byte) {
		if hex.EncodeToString(actual) != expected {
			t.Fatalf("unexpected %s: %s", name, hex.EncodeToString(actual))
		}
	}
	assertHex("send", "d44db8a695c24837c4f3ee2d780c543c4a452e844c548a4f2827c26a3bd09ead", keys.SendKey)
	assertHex("recv", "ca19d7f1d55ed58ae2463d5305b290cfb709289470edb72f9447f5fa10fbfbeb", keys.RecvKey)
	assertHex("mac", "4b6102bd6cd8f9df7ec257b08d496a5c38176a07b735f415f2077a3c29fda385", keys.MACKey)
	assertHex("ratchet", "7caae8bfe0de6ca3559a4d79f726b10f2d8f88b0119130e0c3d1104c11680bc1", keys.RatchetKey)

	keys.Zero()
	for _, key := range [][]byte{keys.SendKey, keys.RecvKey, keys.MACKey, keys.RatchetKey} {
		if !bytes.Equal(key, make([]byte, len(key))) {
			t.Fatal("expected zeroized keys after Zero()")
		}
	}
}

func TestDeriveSessionKeysInvalidHash(t *testing.T) {
	_, err := DeriveSessionKeys([]byte("secret"), nil, nil, crypto.Hash(0), SessionKeySizes{})
	if err == nil {
		t.Fatal("expected error for unavailable hash")
	}
}

func TestHashFromName(t *testing.T) {
	hash, err := HashFromName("sha512")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != crypto.SHA512 {
		t.Fatalf("expected sha512 hash, got %v", hash)
	}
	if _, err := HashFromName("unknown"); err == nil {
		t.Fatal("expected error for unsupported hash")
	}
}
