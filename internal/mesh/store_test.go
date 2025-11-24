package mesh

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
)

func TestStoreMergeMembersAndApps(t *testing.T) {
	self := Member{
		ID:          "self",
		Endpoint:    "127.0.0.1:9000",
		IdentityKey: bytes.Repeat([]byte{1}, ed25519.PublicKeySize),
	}

	store, err := NewStore(self)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	now := time.Now()
	added, updated := store.MergeMembers([]Member{
		{ID: "peer-1", Endpoint: "10.0.0.2:50051", IdentityKey: bytes.Repeat([]byte{2}, ed25519.PublicKeySize)},
	}, now)
	if added != 1 || updated != 0 {
		t.Fatalf("expected 1 added peer, got added=%d updated=%d", added, updated)
	}

	later := now.Add(time.Second)
	if !store.RecordHeartbeat("peer-1", later) {
		t.Fatalf("expected heartbeat to update existing peer")
	}
	peer, ok := store.Member("peer-1")
	if !ok || !peer.LastSeen.Equal(later) {
		t.Fatalf("expected last seen updated, got %+v", peer)
	}

	added, updated = store.MergeMembers([]Member{
		{ID: "peer-1", Endpoint: "10.0.0.2:50052", IdentityKey: bytes.Repeat([]byte{2}, ed25519.PublicKeySize)},
	}, now)
	if added != 0 || updated != 1 {
		t.Fatalf("expected peer update counted once, got added=%d updated=%d", added, updated)
	}

	appMeta := map[string]string{"k": "v"}
	changes := store.MergeApps([]registry.AppPresence{
		{AppID: "app-1", NodeID: "peer-1", SessionID: "s1", Metadata: appMeta, ConnectedAt: now},
	}, now)
	if changes != 1 {
		t.Fatalf("expected to record remote app, got %d changes", changes)
	}
	appMeta["k"] = "mutated"

	store.SetLocalApps([]registry.AppPresence{
		{AppID: "local-app", NodeID: "self", SessionID: "sess-1"},
	}, now)

	apps := store.Apps()
	if len(apps) != 2 {
		t.Fatalf("expected 2 app entries, got %d", len(apps))
	}
	for _, app := range apps {
		if app.AppID == "app-1" && app.Metadata["k"] != "v" {
			t.Fatalf("expected metadata cloned, got %v", app.Metadata)
		}
		if app.AppID == "local-app" && app.NodeID != "self" {
			t.Fatalf("expected local app to be keyed to self, got node %s", app.NodeID)
		}
	}

	if _, ok := store.ResolveApp("app-1"); !ok {
		t.Fatalf("expected to resolve remote app")
	}
	removed := store.RemoveAppsForNode("peer-1")
	if removed != 1 {
		t.Fatalf("expected to drop one app for peer-1, got %d", removed)
	}
	if _, ok := store.ResolveApp("app-1"); ok {
		t.Fatalf("expected remote app to be evicted")
	}

	stale := Member{
		ID:          "stale-peer",
		Endpoint:    "10.0.0.3:50051",
		IdentityKey: bytes.Repeat([]byte{3}, ed25519.PublicKeySize),
		LastSeen:    now.Add(-time.Hour),
	}
	store.Upsert(stale, stale.LastSeen)
	staleCutoff := time.Now().Add(-30 * time.Minute)
	removedMembers := store.EvictStale(staleCutoff)
	if len(removedMembers) != 1 || removedMembers[0].ID != "stale-peer" {
		t.Fatalf("expected stale peer evicted, got %+v", removedMembers)
	}
}

func TestStoreRemoveMember(t *testing.T) {
	self := Member{
		ID:          "self",
		Endpoint:    "127.0.0.1:9000",
		IdentityKey: bytes.Repeat([]byte{1}, ed25519.PublicKeySize),
	}

	store, err := NewStore(self)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	peer := Member{
		ID:          "peer-2",
		Endpoint:    "10.0.0.4:50051",
		IdentityKey: bytes.Repeat([]byte{4}, ed25519.PublicKeySize),
		LastSeen:    time.Now(),
	}
	store.Upsert(peer, peer.LastSeen)
	store.MergeApps([]registry.AppPresence{
		{AppID: "remote-app", NodeID: peer.ID, SessionID: "s-remote"},
	}, time.Now())

	removed, ok := store.RemoveMember(peer.ID)
	if !ok || removed.ID != peer.ID {
		t.Fatalf("expected peer removed, got ok=%v removed=%+v", ok, removed)
	}
	if _, exists := store.Member(peer.ID); exists {
		t.Fatalf("expected member to be gone")
	}
	if _, ok := store.ResolveApp("remote-app"); ok {
		t.Fatalf("expected apps for peer to be evicted")
	}
}
