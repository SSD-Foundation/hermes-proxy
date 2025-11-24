package mesh

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestJoinAuthenticatesAndSharesSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	nodeA := newTestMeshNode(t, "node-a")

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	t.Cleanup(func() { srv.Stop(); lis.Close() })
	nodemeshpb.RegisterNodeMeshServer(srv, nodeA.svc)

	go func() {
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.DialContext(ctx, lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	client := nodemeshpb.NewNodeMeshClient(conn)

	nodeB := newTestMeshNode(t, "node-b")
	nonce := []byte("nonce-1234")
	req := &nodemeshpb.JoinRequest{
		Node:  descriptorFromMember(nodeB.identity.Member),
		Nonce: nonce,
	}
	req.Signature = ed25519.Sign(nodeB.identity.PrivateKey, joinPayload(req.Node, nonce))

	resp, err := client.Join(ctx, req)
	if err != nil {
		t.Fatalf("join failed: %v", err)
	}
	if len(resp.Membership) != 2 {
		t.Fatalf("expected membership of 2 nodes, got %d", len(resp.Membership))
	}
	if _, ok := nodeA.store.Member("node-b"); !ok {
		t.Fatalf("expected node-a store to record node-b")
	}

	badReq := proto.Clone(req).(*nodemeshpb.JoinRequest)
	badReq.Signature = []byte("bad")
	if _, err := client.Join(ctx, badReq); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated for bad signature, got %v", err)
	}
}

func TestGossipMembershipFailRemovesPeerAndApps(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	self := Member{
		ID:          "node-a",
		Endpoint:    "127.0.0.1:0",
		IdentityKey: pub,
		LastSeen:    time.Now(),
	}
	store, err := NewStore(self)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	peerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	now := time.Now()
	store.Upsert(Member{ID: "node-b", Endpoint: "127.0.0.1:1234", IdentityKey: peerPub, LastSeen: now}, now)
	store.MergeApps([]registry.AppPresence{{AppID: "remote-app", NodeID: "node-b", SessionID: "sess-1"}}, now)

	removedCh := make(chan string, 1)
	svc, err := NewService(ServiceConfig{
		Log:           zaptest.NewLogger(t),
		Store:         store,
		Identity:      Identity{Member: self, PrivateKey: priv},
		OnPeerRemoved: func(m Member) { removedCh <- m.ID },
	})
	if err != nil {
		t.Fatalf("init service: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	t.Cleanup(func() {
		grpcSrv.Stop()
		lis.Close()
	})
	nodemeshpb.RegisterNodeMeshServer(grpcSrv, svc)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.DialContext(ctx, lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	client := nodemeshpb.NewNodeMeshClient(conn)
	stream, err := client.Gossip(ctx)
	if err != nil {
		t.Fatalf("open gossip: %v", err)
	}

	if err := stream.Send(&nodemeshpb.GossipMessage{
		Body: &nodemeshpb.GossipMessage_Membership{
			Membership: &nodemeshpb.MembershipEvent{
				Type: nodemeshpb.MembershipEvent_TYPE_FAIL,
				Node: &nodemeshpb.NodeDescriptor{
					NodeId:      "node-b",
					Endpoint:    "127.0.0.1:1234",
					IdentityKey: peerPub,
				},
			},
		},
	}); err != nil {
		t.Fatalf("send membership: %v", err)
	}

	select {
	case <-removedCh:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for peer removal callback")
	}
	if _, ok := store.Member("node-b"); ok {
		t.Fatalf("expected node-b removed from store")
	}
	if _, ok := store.ResolveApp("remote-app"); ok {
		t.Fatalf("expected remote apps removed with membership fail")
	}
}

type testMeshNode struct {
	identity Identity
	store    *Store
	svc      *Service
}

func newTestMeshNode(t *testing.T, id string) testMeshNode {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	member := Member{
		ID:          id,
		Endpoint:    "127.0.0.1:0",
		IdentityKey: pub,
		LastSeen:    time.Now(),
	}
	store, err := NewStore(member)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	svc, err := NewService(ServiceConfig{
		Log:      zaptest.NewLogger(t),
		Store:    store,
		Identity: Identity{Member: member, PrivateKey: priv},
	})
	if err != nil {
		t.Fatalf("init service: %v", err)
	}

	return testMeshNode{
		identity: Identity{Member: member, PrivateKey: priv},
		store:    store,
		svc:      svc,
	}
}
