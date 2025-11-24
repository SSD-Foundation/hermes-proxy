package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/mesh"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
)

func TestCrossNodeRoutingHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	nodeA := startMeshTestNode(t, "node-a")
	nodeB := startMeshTestNode(t, "node-b")
	defer nodeA.stop()
	defer nodeB.stop()

	now := time.Now()
	nodeA.store.MergeMembers([]mesh.Member{nodeB.member}, now)
	nodeB.store.MergeMembers([]mesh.Member{nodeA.member}, now)

	connA := dialClient(t, ctx, nodeA.addr)
	connB := dialClient(t, ctx, nodeB.addr)
	t.Cleanup(func() {
		connA.Close()
		connB.Close()
	})

	clientA := approuterpb.NewAppRouterClient(connA)
	clientB := approuterpb.NewAppRouterClient(connB)

	streamA, err := clientA.Open(ctx)
	if err != nil {
		t.Fatalf("open stream A: %v", err)
	}
	streamB, err := clientB.Open(ctx)
	if err != nil {
		t.Fatalf("open stream B: %v", err)
	}

	appAPub, appAPriv := mustKeypair(t)
	appBPub, appBPriv := mustKeypair(t)
	appAID := appIdentityKey(appAPub)
	appBID := appIdentityKey(appBPub)

	sendConnectFrame(t, streamA, nodeA.id, appAPub, appAPriv, nil)
	sendConnectFrame(t, streamB, nodeB.id, appBPub, appBPriv, nil)
	expectConnectAck(t, streamA)
	expectConnectAck(t, streamB)

	now = time.Now()
	nodeA.store.MergeApps(nodeB.store.Apps(), now)
	nodeB.store.MergeApps(nodeA.store.Apps(), now)

	chatID := "cross-node-chat"
	ephA := mustEphemeral(t)
	ephB := mustEphemeral(t)

	sendStartChat(t, streamA, chatID, appBID, ephA, appAPriv)
	expectStartChatAck(t, streamA, chatID)
	sendStartChat(t, streamB, chatID, appAID, ephB, appBPriv)
	expectStartChatAck(t, streamB, chatID)

	peerA := waitForStartChat(t, streamA)
	if !bytes.Equal(peerA.LocalEphemeralPublicKey, ephB.Public) {
		t.Fatalf("node A expected peer key %x, got %x", ephB.Public, peerA.LocalEphemeralPublicKey)
	}
	peerB := waitForStartChat(t, streamB)
	if !bytes.Equal(peerB.LocalEphemeralPublicKey, ephA.Public) {
		t.Fatalf("node B expected peer key %x, got %x", ephA.Public, peerB.LocalEphemeralPublicKey)
	}
	if peerA.KeyVersion != 1 || peerB.KeyVersion != 1 {
		t.Fatalf("expected key version 1, got %d and %d", peerA.KeyVersion, peerB.KeyVersion)
	}
	if peerA.HkdfInfo != "hermes-chat-session" || peerB.HkdfInfo != "hermes-chat-session" {
		t.Fatalf("unexpected hkdf info in remote start chat")
	}
	waitForSecret := func(ks *memoryKeystore, id string) keystore.ChatSecretRecord {
		for i := 0; i < 10; i++ {
			if ks.has(id) {
				rec, err := ks.LoadChatSecret(context.Background(), id)
				if err == nil {
					return rec
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		return keystore.ChatSecretRecord{}
	}
	if rec := waitForSecret(nodeA.ks, chatID); rec.ChatID == "" {
		t.Fatalf("nodeA expected chat secret")
	} else if rec.KeyVersion != 1 {
		t.Fatalf("nodeA expected key version 1, got %d", rec.KeyVersion)
	}
	if rec := waitForSecret(nodeB.ks, chatID); rec.ChatID == "" {
		t.Fatalf("nodeB expected chat secret")
	} else if rec.KeyVersion != 1 {
		t.Fatalf("nodeB expected key version 1, got %d", rec.KeyVersion)
	}

	payload := []byte("0123456789abcdefpayload")
	if err := streamA.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  payload,
				Sequence: 1,
			},
		},
	}); err != nil {
		t.Fatalf("send cross-node chat: %v", err)
	}

	expectChatAck(t, streamA, chatID, 1)
	msgB := waitForChatMessage(t, streamB)
	if msgB.ChatId != chatID || msgB.Sequence != 1 {
		t.Fatalf("unexpected forwarded message: %+v", msgB)
	}

	if err := streamA.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_DeleteChat{
			DeleteChat: &approuterpb.DeleteChat{ChatId: chatID, Reason: "done"},
		},
	}); err != nil {
		t.Fatalf("send delete chat: %v", err)
	}

	expectDeleteAck(t, streamA, "deleted")
	expectDeleteAck(t, streamB, "deleted_by_peer")

	if nodeA.ks.has(chatID) || nodeB.ks.has(chatID) {
		t.Fatalf("expected secrets wiped on both nodes")
	}
}

func TestCrossNodeUnknownTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	nodeA := startMeshTestNode(t, "node-a")
	defer nodeA.stop()

	conn := dialClient(t, ctx, nodeA.addr)
	t.Cleanup(func() { conn.Close() })

	client := approuterpb.NewAppRouterClient(conn)
	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	appPub, appPriv := mustKeypair(t)
	sendConnectFrame(t, stream, nodeA.id, appPub, appPriv, nil)
	expectConnectAck(t, stream)

	eph := mustEphemeral(t)
	appID := appIdentityKey(appPub)
	payload := handshakePayload("missing-chat", appID, "missing-target", eph.Public, nil, "hermes-chat-session", 1, false)
	if err := stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                   "missing-chat",
				TargetAppId:              "missing-target",
				TargetNodeHint:           "missing-node",
				LocalEphemeralPublicKey:  eph.Public,
				LocalEphemeralPrivateKey: eph.Private,
				Signature:                ed25519.Sign(appPriv, payload),
				KeyVersion:               1,
				HkdfInfo:                 "hermes-chat-session",
			},
		},
	}); err != nil {
		t.Fatalf("send start chat: %v", err)
	}

	// StartChatAck may arrive before the route error; consume frames until an error is observed.
	var errFrame *approuterpb.Error
	for i := 0; i < 2; i++ {
		frame := recvFrame(t, stream)
		if e, ok := frame.Body.(*approuterpb.AppFrame_Error); ok {
			errFrame = e.Error
			break
		}
	}
	if errFrame == nil {
		t.Fatalf("expected error frame after StartChat with missing target")
	}
	if errFrame.Code != "ROUTE_UNAVAILABLE" && errFrame.Code != "TARGET_NOT_FOUND" {
		t.Fatalf("unexpected error code %s", errFrame.Code)
	}
}

func TestCrossNodeRouteLossTriggersTeardown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	nodeA := startMeshTestNode(t, "node-a")
	nodeB := startMeshTestNode(t, "node-b")
	defer nodeA.stop()
	defer nodeB.stop()

	now := time.Now()
	nodeA.store.MergeMembers([]mesh.Member{nodeB.member}, now)
	nodeB.store.MergeMembers([]mesh.Member{nodeA.member}, now)

	connA := dialClient(t, ctx, nodeA.addr)
	connB := dialClient(t, ctx, nodeB.addr)
	t.Cleanup(func() {
		connA.Close()
		connB.Close()
	})

	clientA := approuterpb.NewAppRouterClient(connA)
	clientB := approuterpb.NewAppRouterClient(connB)

	streamA, err := clientA.Open(ctx)
	if err != nil {
		t.Fatalf("open stream A: %v", err)
	}
	streamB, err := clientB.Open(ctx)
	if err != nil {
		t.Fatalf("open stream B: %v", err)
	}

	appAPub, appAPriv := mustKeypair(t)
	appBPub, appBPriv := mustKeypair(t)
	appAID := appIdentityKey(appAPub)
	appBID := appIdentityKey(appBPub)

	sendConnectFrame(t, streamA, nodeA.id, appAPub, appAPriv, nil)
	sendConnectFrame(t, streamB, nodeB.id, appBPub, appBPriv, nil)
	expectConnectAck(t, streamA)
	expectConnectAck(t, streamB)

	now = time.Now()
	nodeA.store.MergeApps(nodeB.store.Apps(), now)
	nodeB.store.MergeApps(nodeA.store.Apps(), now)

	chatID := "route-loss"
	sendStartChat(t, streamA, chatID, appBID, mustEphemeral(t), appAPriv)
	expectStartChatAck(t, streamA, chatID)
	sendStartChat(t, streamB, chatID, appAID, mustEphemeral(t), appBPriv)
	expectStartChatAck(t, streamB, chatID)

	_ = waitForStartChat(t, streamA)
	_ = waitForStartChat(t, streamB)

	nodeB.stop()

	frame := recvFrame(t, streamA)
	ack, ok := frame.Body.(*approuterpb.AppFrame_DeleteChatAck)
	if !ok {
		t.Fatalf("expected DeleteChatAck after route loss, got %T", frame.Body)
	}
	if ack.DeleteChatAck.Status != "route_closed" {
		t.Fatalf("expected route_closed status, got %s", ack.DeleteChatAck.Status)
	}
}

type meshTestNode struct {
	id     string
	addr   string
	router *AppRouterService
	store  *mesh.Store
	member mesh.Member
	ks     *memoryKeystore
	srv    *grpc.Server
	stopFn func()
}

func startMeshTestNode(t *testing.T, id string) meshTestNode {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}

	member := mesh.Member{
		ID:          id,
		Endpoint:    lis.Addr().String(),
		IdentityKey: pub,
		LastSeen:    time.Now(),
	}

	store, err := mesh.NewStore(member)
	if err != nil {
		t.Fatalf("mesh store: %v", err)
	}

	registryMetrics := prometheus.NewRegistry()
	svc, err := mesh.NewService(mesh.ServiceConfig{
		Log:      zaptest.NewLogger(t),
		Store:    store,
		Metrics:  mesh.NewMetrics(registryMetrics),
		Identity: mesh.Identity{Member: member, PrivateKey: priv},
	})
	if err != nil {
		t.Fatalf("mesh service: %v", err)
	}

	ks := newMemoryKeystore()
	reg := registry.NewInMemory(0)
	router := NewAppRouterService(zaptest.NewLogger(t), reg, ks, RouterOptions{
		NodeID:    id,
		Apps:      registry.NewAppRegistry(),
		MeshStore: store,
	})

	routePool, err := mesh.NewRouteClientPool(mesh.RouteClientConfig{
		Log:         zaptest.NewLogger(t),
		Store:       store,
		TLS:         mesh.TLSConfig{},
		Handler:     router,
		NodeID:      id,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("route pool: %v", err)
	}
	router.routes = routePool
	router.store = store
	svc.AttachRouter(router)

	srv := grpc.NewServer()
	approuterpb.RegisterAppRouterServer(srv, router)
	nodemeshpb.RegisterNodeMeshServer(srv, svc)

	go func() {
		_ = srv.Serve(lis)
	}()

	return meshTestNode{
		id:     id,
		addr:   lis.Addr().String(),
		router: router,
		store:  store,
		member: member,
		ks:     ks,
		srv:    srv,
		stopFn: func() {
			srv.Stop()
			lis.Close()
		},
	}
}

func (n meshTestNode) stop() {
	if n.stopFn != nil {
		n.stopFn()
	}
}
