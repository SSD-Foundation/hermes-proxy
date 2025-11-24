package pfs

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the length of X25519 public/private keys and derived session keys.
	KeySize = 32
)

// KeyPair holds an X25519 key pair and a deterministic identifier derived from the public key.
type KeyPair struct {
	Public  []byte
	Private []byte
	ID      string
}

// SessionKeys groups HKDF-derived keys for send/receive, MAC, and ratcheting.
type SessionKeys struct {
	SendKey    []byte
	RecvKey    []byte
	MACKey     []byte
	RatchetKey []byte
}

// SessionKeySizes allows overriding HKDF output lengths; zero values default to KeySize.
type SessionKeySizes struct {
	Send    int
	Recv    int
	MAC     int
	Ratchet int
}

var (
	curve          = ecdh.X25519()
	validationPriv *ecdh.PrivateKey
)

func init() {
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Errorf("init validation key: %w", err))
	}
	validationPriv = priv
}

// GenerateKeyPair produces a fresh X25519 key pair using the provided source of randomness.
func GenerateKeyPair(r io.Reader) (KeyPair, error) {
	if r == nil {
		r = rand.Reader
	}
	priv, err := curve.GenerateKey(r)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generate x25519 key: %w", err)
	}
	pub := priv.PublicKey()
	id, err := KeyIdentifier(pub.Bytes())
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{
		Public:  append([]byte(nil), pub.Bytes()...),
		Private: append([]byte(nil), priv.Bytes()...),
		ID:      id,
	}, nil
}

// ValidatePublicKey ensures the provided key has the expected size and does not yield a zero shared secret.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != KeySize {
		return fmt.Errorf("public key must be %d bytes (got %d)", KeySize, len(pub))
	}
	parsed, err := curve.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	secret, err := validationPriv.ECDH(parsed)
	if err != nil {
		return fmt.Errorf("derive test shared secret: %w", err)
	}
	defer zeroBytes(secret)
	if isZero(secret) {
		return fmt.Errorf("public key yielded low-entropy shared secret")
	}
	return nil
}

// KeyIdentifier returns a deterministic identifier derived from the SHA-256 hash of the public key.
func KeyIdentifier(pub []byte) (string, error) {
	if len(pub) != KeySize {
		return "", fmt.Errorf("public key must be %d bytes (got %d)", KeySize, len(pub))
	}
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// SharedSecret computes the X25519 shared secret for the provided private/public key pair.
func SharedSecret(private, peerPublic []byte) ([]byte, error) {
	if len(private) != KeySize {
		return nil, fmt.Errorf("private key must be %d bytes (got %d)", KeySize, len(private))
	}
	if err := ValidatePublicKey(peerPublic); err != nil {
		return nil, err
	}

	privKey, err := curve.NewPrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pubKey, err := curve.NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}

	secret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}
	if isZero(secret) {
		return nil, fmt.Errorf("shared secret is all zeros")
	}
	return secret, nil
}

// DeriveSessionKeys expands the shared secret with HKDF using the provided hash, salt, and info label.
func DeriveSessionKeys(sharedSecret, salt, info []byte, hash crypto.Hash, sizes SessionKeySizes) (SessionKeys, error) {
	if len(sharedSecret) == 0 {
		return SessionKeys{}, fmt.Errorf("shared secret required")
	}
	if !hash.Available() {
		return SessionKeys{}, fmt.Errorf("hash %v is unavailable", hash)
	}

	sizes = fillSizes(sizes)
	reader := hkdf.New(hash.New, sharedSecret, salt, info)

	keys := SessionKeys{
		SendKey:    make([]byte, sizes.Send),
		RecvKey:    make([]byte, sizes.Recv),
		MACKey:     make([]byte, sizes.MAC),
		RatchetKey: make([]byte, sizes.Ratchet),
	}
	if _, err := io.ReadFull(reader, keys.SendKey); err != nil {
		keys.Zero()
		return SessionKeys{}, fmt.Errorf("derive send key: %w", err)
	}
	if _, err := io.ReadFull(reader, keys.RecvKey); err != nil {
		keys.Zero()
		return SessionKeys{}, fmt.Errorf("derive recv key: %w", err)
	}
	if _, err := io.ReadFull(reader, keys.MACKey); err != nil {
		keys.Zero()
		return SessionKeys{}, fmt.Errorf("derive mac key: %w", err)
	}
	if _, err := io.ReadFull(reader, keys.RatchetKey); err != nil {
		keys.Zero()
		return SessionKeys{}, fmt.Errorf("derive ratchet key: %w", err)
	}
	return keys, nil
}

// Zero overwrites derived keys in-place.
func (s *SessionKeys) Zero() {
	zeroBytes(s.SendKey)
	zeroBytes(s.RecvKey)
	zeroBytes(s.MACKey)
	zeroBytes(s.RatchetKey)
}

func fillSizes(in SessionKeySizes) SessionKeySizes {
	out := SessionKeySizes{
		Send:    in.Send,
		Recv:    in.Recv,
		MAC:     in.MAC,
		Ratchet: in.Ratchet,
	}
	if out.Send == 0 {
		out.Send = KeySize
	}
	if out.Recv == 0 {
		out.Recv = KeySize
	}
	if out.MAC == 0 {
		out.MAC = KeySize
	}
	if out.Ratchet == 0 {
		out.Ratchet = KeySize
	}
	return out
}

func isZero(b []byte) bool {
	acc := byte(0)
	for _, v := range b {
		acc |= v
	}
	return acc == 0
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HashFromName maps a human-readable hash identifier to a crypto.Hash.
func HashFromName(name string) (crypto.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha256":
		return crypto.SHA256, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hkdf hash %q", name)
	}
}
