package keystore

import (
	"errors"
	"fmt"
	"time"
)

const (
	chatSecretVersion  = 1
	x25519KeySize      = 32
	maxSecretBytes     = 16 * 1024
	maxChatSecretBytes = 8 * 1024
	maxHKDFSaltSize    = 64
	maxHKDFInfoSize    = 256
)

var (
	ErrInvalidChatSecret = errors.New("invalid chat secret")
	ErrChatSecretTooBig  = errors.New("chat secret exceeds size limit")
)

// ChatSecretRecord stores per-chat key material and metadata in a sealed keystore record.
type ChatSecretRecord struct {
	Version        int       `json:"version"`
	ChatID         string    `json:"chat_id"`
	KeyVersion     uint32    `json:"key_version"`
	LocalKeyID     string    `json:"local_key_id,omitempty"`
	RemoteKeyID    string    `json:"remote_key_id,omitempty"`
	LocalPublic    []byte    `json:"local_public,omitempty"`
	RemotePublic   []byte    `json:"remote_public,omitempty"`
	LocalPrivate   []byte    `json:"local_private,omitempty"`
	HKDFSalt       []byte    `json:"hkdf_salt,omitempty"`
	HKDFInfo       []byte    `json:"hkdf_info,omitempty"`
	SendKey        []byte    `json:"send_key,omitempty"`
	RecvKey        []byte    `json:"recv_key,omitempty"`
	MACKey         []byte    `json:"mac_key,omitempty"`
	RatchetSeed    []byte    `json:"ratchet_seed,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	RotatedAt      time.Time `json:"rotated_at,omitempty"`
	LegacyCombined []byte    `json:"legacy_combined,omitempty"`
}

// Clone returns a deep copy of the record to avoid exposing internal buffers.
func (c ChatSecretRecord) Clone() ChatSecretRecord {
	out := c
	out.LocalPublic = cloneBytes(c.LocalPublic)
	out.RemotePublic = cloneBytes(c.RemotePublic)
	out.LocalPrivate = cloneBytes(c.LocalPrivate)
	out.HKDFSalt = cloneBytes(c.HKDFSalt)
	out.HKDFInfo = cloneBytes(c.HKDFInfo)
	out.SendKey = cloneBytes(c.SendKey)
	out.RecvKey = cloneBytes(c.RecvKey)
	out.MACKey = cloneBytes(c.MACKey)
	out.RatchetSeed = cloneBytes(c.RatchetSeed)
	out.LegacyCombined = cloneBytes(c.LegacyCombined)
	return out
}

// Zero overwrites sensitive fields in-place.
func (c *ChatSecretRecord) Zero() {
	zeroBytes(c.LocalPublic)
	zeroBytes(c.RemotePublic)
	zeroBytes(c.LocalPrivate)
	zeroBytes(c.HKDFSalt)
	zeroBytes(c.HKDFInfo)
	zeroBytes(c.SendKey)
	zeroBytes(c.RecvKey)
	zeroBytes(c.MACKey)
	zeroBytes(c.RatchetSeed)
	zeroBytes(c.LegacyCombined)
}

func normalizeChatSecret(in ChatSecretRecord, now time.Time) (ChatSecretRecord, error) {
	if in.ChatID == "" {
		return ChatSecretRecord{}, ErrInvalidSecretID
	}
	out := in.Clone()
	if now.IsZero() {
		now = time.Now()
	}
	if out.Version == 0 {
		out.Version = chatSecretVersion
	}
	if out.Version != chatSecretVersion {
		return ChatSecretRecord{}, fmt.Errorf("unsupported chat secret version %d: %w", out.Version, ErrInvalidChatSecret)
	}
	if out.KeyVersion == 0 {
		out.KeyVersion = 1
	}
	if out.CreatedAt.IsZero() {
		out.CreatedAt = now.UTC()
	}
	if !out.RotatedAt.IsZero() {
		out.RotatedAt = out.RotatedAt.UTC()
	}
	if err := validateChatSecret(out); err != nil {
		return ChatSecretRecord{}, err
	}
	return out, nil
}

func validateChatSecret(rec ChatSecretRecord) error {
	if err := validateKeySize(rec.LocalPublic, "local_public"); err != nil {
		return err
	}
	if err := validateKeySize(rec.RemotePublic, "remote_public"); err != nil {
		return err
	}
	if err := validateKeySize(rec.LocalPrivate, "local_private"); err != nil {
		return err
	}
	if l := len(rec.HKDFSalt); l > maxHKDFSaltSize {
		return fmt.Errorf("hkdf salt too large (%d bytes, max %d): %w", l, maxHKDFSaltSize, ErrInvalidChatSecret)
	}
	if l := len(rec.HKDFInfo); l > maxHKDFInfoSize {
		return fmt.Errorf("hkdf info too large (%d bytes, max %d): %w", l, maxHKDFInfoSize, ErrInvalidChatSecret)
	}
	for name, key := range map[string][]byte{
		"send_key":     rec.SendKey,
		"recv_key":     rec.RecvKey,
		"mac_key":      rec.MACKey,
		"ratchet_seed": rec.RatchetSeed,
	} {
		if len(key) > 0 && len(key) != x25519KeySize {
			return fmt.Errorf("%s must be %d bytes when set (got %d): %w", name, x25519KeySize, len(key), ErrInvalidChatSecret)
		}
	}

	if size := chatSecretSize(rec); size > maxChatSecretBytes {
		return fmt.Errorf("chat secret is %d bytes (limit %d): %w", size, maxChatSecretBytes, ErrChatSecretTooBig)
	}
	return nil
}

func validateKeySize(key []byte, field string) error {
	if len(key) > 0 && len(key) != x25519KeySize {
		return fmt.Errorf("%s must be %d bytes (got %d): %w", field, x25519KeySize, len(key), ErrInvalidChatSecret)
	}
	return nil
}

func chatSecretSize(rec ChatSecretRecord) int {
	total := len(rec.ChatID) + len(rec.LocalKeyID) + len(rec.RemoteKeyID)
	total += len(rec.LocalPublic) + len(rec.RemotePublic) + len(rec.LocalPrivate)
	total += len(rec.HKDFSalt) + len(rec.HKDFInfo)
	total += len(rec.SendKey) + len(rec.RecvKey) + len(rec.MACKey) + len(rec.RatchetSeed)
	total += len(rec.LegacyCombined)
	return total
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
