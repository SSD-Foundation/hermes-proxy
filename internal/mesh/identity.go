package mesh

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
)

// Identity holds the node's long-term keys and metadata.
type Identity struct {
	Member     Member
	PrivateKey ed25519.PrivateKey
}

// EnsureIdentityKey loads the node identity key from the keystore or generates it.
func EnsureIdentityKey(ctx context.Context, ks keystore.KeyBackend, secretID string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if ks == nil {
		return nil, nil, errors.New("keystore is required for mesh identity")
	}
	if secretID == "" {
		secretID = "mesh_identity"
	}

	raw, err := ks.LoadSecret(ctx, secretID)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("load mesh identity: %w", err)
		}
		pub, priv, genErr := ed25519.GenerateKey(nil)
		if genErr != nil {
			return nil, nil, fmt.Errorf("generate mesh identity: %w", genErr)
		}
		if storeErr := ks.StoreSecret(ctx, secretID, priv); storeErr != nil {
			return nil, nil, fmt.Errorf("store mesh identity: %w", storeErr)
		}
		return append([]byte(nil), pub...), append([]byte(nil), priv...), nil
	}
	defer zeroBytes(raw)

	if len(raw) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("mesh identity secret has invalid size %d", len(raw))
	}

	priv := ed25519.PrivateKey(append([]byte(nil), raw...))
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
