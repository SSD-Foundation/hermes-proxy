package mesh

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
)

func TestDialerEvictsStalePeersAndNotifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	self := Member{
		ID:          "self",
		Endpoint:    "127.0.0.1:0",
		IdentityKey: pub,
		LastSeen:    time.Now(),
	}
	store, err := NewStore(self)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	stale := Member{
		ID:          "stale-peer",
		Endpoint:    "127.0.0.1:1234",
		IdentityKey: pub,
		LastSeen:    time.Now().Add(-time.Second),
	}
	store.Upsert(stale, stale.LastSeen)

	evicted := make(chan string, 1)
	dialer, err := NewDialer(DialerConfig{
		Log:               zaptest.NewLogger(t),
		Store:             store,
		Identity:          Identity{Member: self, PrivateKey: priv},
		Interval:          time.Millisecond,
		HeartbeatInterval: 5 * time.Millisecond,
		SuspectAfter:      5 * time.Millisecond,
		EvictAfter:        10 * time.Millisecond,
		Metrics:           NewMetrics(prometheus.NewRegistry()),
		OnPeerEvicted: func(m Member) {
			evicted <- m.ID
		},
	})
	if err != nil {
		t.Fatalf("new dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	go dialer.watchdog(ctx)

	select {
	case id := <-evicted:
		if id != stale.ID {
			t.Fatalf("expected %s evicted, got %s", stale.ID, id)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for eviction")
	}
}
