package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestAppRouterHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	addr, stop, reg, ks := startTestRouter(t)
	t.Cleanup(stop)

	conn1 := dialClient(t, ctx, addr)
	t.Cleanup(func() { conn1.Close() })
	conn2 := dialClient(t, ctx, addr)
	t.Cleanup(func() { conn2.Close() })

	client1 := approuterpb.NewAppRouterClient(conn1)
	client2 := approuterpb.NewAppRouterClient(conn2)

	stream1, err := client1.Open(ctx)
	if err != nil {
		t.Fatalf("open stream1: %v", err)
	}
	stream2, err := client2.Open(ctx)
	if err != nil {
		t.Fatalf("open stream2: %v", err)
	}

	// handshake
	app1Pub, app1Priv := mustKeypair(t)
	app2Pub, app2Priv := mustKeypair(t)
	app1ID := appIdentityKey(app1Pub)
	app2ID := appIdentityKey(app2Pub)
	nodeID := "node-1"

	sendConnectFrame(t, stream1, nodeID, app1Pub, app1Priv, nil)
	sendConnectFrame(t, stream2, nodeID, app2Pub, app2Priv, nil)

	expectConnectAck(t, stream1)
	expectConnectAck(t, stream2)

	// start chat with signed ephemeral keys
	chatID := "chat-123"
	eph1 := mustRandBytes(t, 32)
	eph2 := mustRandBytes(t, 32)
	sendStartChat(t, stream1, chatID, app2ID, eph1, app1Priv)
	expectStartChatAck(t, stream1, chatID)
	sendStartChat(t, stream2, chatID, app1ID, eph2, app2Priv)
	expectStartChatAck(t, stream2, chatID)

	peer1 := waitForStartChat(t, stream1)
	if !bytes.Equal(peer1.PeerPublicEphemeralKey, eph2) {
		t.Fatalf("client1 expected peer ephemeral %x, got %x", eph2, peer1.PeerPublicEphemeralKey)
	}
	peer2 := waitForStartChat(t, stream2)
	if !bytes.Equal(peer2.PeerPublicEphemeralKey, eph1) {
		t.Fatalf("client2 expected peer ephemeral %x, got %x", eph1, peer2.PeerPublicEphemeralKey)
	}

	// message relay and ordering
	payload := []byte("0123456789abcdefpayload")
	if err := stream1.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  payload,
				Sequence: 1,
			},
		},
	}); err != nil {
		t.Fatalf("send chat message: %v", err)
	}

	expectChatAck(t, stream1, chatID, 1)
	received := waitForChatMessage(t, stream2)
	if received.ChatId != chatID || received.Sequence != 1 {
		t.Fatalf("unexpected forwarded message: %+v", received)
	}
	if !bytes.Equal(received.Payload, payload) {
		t.Fatalf("payload mismatch: %x vs %x", received.Payload, payload)
	}

	// delete chat tears down both sides and erases secret
	if err := stream1.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_DeleteChat{
			DeleteChat: &approuterpb.DeleteChat{ChatId: chatID, Reason: "done"},
		},
	}); err != nil {
		t.Fatalf("send delete chat: %v", err)
	}

	expectDeleteAck(t, stream1, "deleted")
	expectDeleteAck(t, stream2, "deleted_by_peer")

	if chats := reg.List(); len(chats) != 0 {
		t.Fatalf("expected registry empty after delete, got %d", len(chats))
	}
	if ks.has(chatID) {
		t.Fatalf("expected keystore secret erased for %s", chatID)
	}
}

func TestStartChatSignatureFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	addr, stop, reg, ks := startTestRouter(t)
	t.Cleanup(stop)

	conn := dialClient(t, ctx, addr)
	t.Cleanup(func() { conn.Close() })
	client := approuterpb.NewAppRouterClient(conn)

	stream, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	appPub, appPriv := mustKeypair(t)
	sendConnectFrame(t, stream, "node-1", appPub, appPriv, nil)
	expectConnectAck(t, stream)

	// invalid signature: empty bytes
	if err := stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                 "bad-chat",
				TargetAppId:            "unknown",
				PeerPublicEphemeralKey: mustRandBytes(t, 32),
				Signature:              []byte{},
			},
		},
	}); err != nil {
		t.Fatalf("send start chat: %v", err)
	}

	frame := recvFrame(t, stream)
	errFrame, ok := frame.Body.(*approuterpb.AppFrame_Error)
	if !ok {
		t.Fatalf("expected error frame, got %T", frame.Body)
	}
	if errFrame.Error.Code != "AUTH_FAILED" {
		t.Fatalf("expected AUTH_FAILED code, got %s", errFrame.Error.Code)
	}

	if chats := reg.List(); len(chats) != 0 {
		t.Fatalf("expected no chats recorded, got %d", len(chats))
	}
	if ks.has("bad-chat") {
		t.Fatalf("keystore should not store secrets on failed start")
	}
}

func TestIdleChatExpiry(t *testing.T) {
	reg := registry.NewInMemory(0)
	ks := newMemoryKeystore()
	svc := NewAppRouterService(zaptest.NewLogger(t), reg, ks, RouterOptions{
		ChatIdleTimeout:      10 * time.Millisecond,
		HousekeepingInterval: 5 * time.Millisecond,
	})

	session1 := &appSession{
		id:       "s1",
		sendCh:   make(chan *approuterpb.AppFrame, 2),
		ctx:      context.Background(),
		cancel:   func() {},
		lastSeen: time.Now(),
	}
	session2 := &appSession{
		id:       "s2",
		sendCh:   make(chan *approuterpb.AppFrame, 2),
		ctx:      context.Background(),
		cancel:   func() {},
		lastSeen: time.Now(),
	}

	tl := newTieline("chat-expire")
	tl.participants[session1.id] = &chatParticipant{session: session1}
	tl.participants[session2.id] = &chatParticipant{session: session2}
	tl.lastActivity = time.Now().Add(-time.Minute)

	_ = reg.Register(registry.ChatSession{ChatID: "chat-expire"})
	if err := ks.StoreSecret(context.Background(), "chat-expire", []byte("secret")); err != nil {
		t.Fatalf("seed keystore: %v", err)
	}

	svc.mu.Lock()
	svc.chats["chat-expire"] = tl
	svc.mu.Unlock()

	svc.expireIdleChats(time.Now())

	if _, ok := reg.Get("chat-expire"); ok {
		t.Fatalf("expected registry entry removed after expiry")
	}
	if ks.has("chat-expire") {
		t.Fatalf("expected keystore secret removed after expiry")
	}

	expectExpired := func(ch <-chan *approuterpb.AppFrame) {
		select {
		case frame := <-ch:
			ack, ok := frame.Body.(*approuterpb.AppFrame_DeleteChatAck)
			if !ok {
				t.Fatalf("expected DeleteChatAck, got %T", frame.Body)
			}
			if ack.DeleteChatAck.Status != "expired" {
				t.Fatalf("expected status expired, got %s", ack.DeleteChatAck.Status)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for expiry ack")
		}
	}

	expectExpired(session1.sendCh)
	expectExpired(session2.sendCh)
}

func startTestRouter(t *testing.T) (addr string, stop func(), reg registry.ChatRegistry, ks *memoryKeystore) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	reg = registry.NewInMemory(0)
	ks = newMemoryKeystore()
	srv := grpc.NewServer()
	approuterpb.RegisterAppRouterServer(srv, NewAppRouterService(zaptest.NewLogger(t), reg, ks, RouterOptions{}))

	go func() {
		if serveErr := srv.Serve(listener); serveErr != nil {
			t.Logf("gRPC serve error: %v", serveErr)
		}
	}()

	stop = func() {
		srv.Stop()
		listener.Close()
	}
	return listener.Addr().String(), stop, reg, ks
}

func dialClient(t *testing.T, ctx context.Context, addr string) *grpc.ClientConn {
	t.Helper()

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func sendConnectFrame(t *testing.T, stream approuterpb.AppRouter_OpenClient, nodeID string, pub ed25519.PublicKey, priv ed25519.PrivateKey, metadata map[string]string) {
	t.Helper()
	payload := connectSignaturePayload(&approuterpb.Connect{NodeId: nodeID, Metadata: metadata})
	sig := ed25519.Sign(priv, payload)
	if err := stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_Connect{
			Connect: &approuterpb.Connect{
				AppPublicKey: pub,
				Signature:    sig,
				NodeId:       nodeID,
				Metadata:     metadata,
			},
		},
	}); err != nil {
		t.Fatalf("send connect: %v", err)
	}
}

func sendStartChat(t *testing.T, stream approuterpb.AppRouter_OpenClient, chatID, targetAppID string, eph []byte, priv ed25519.PrivateKey) {
	t.Helper()
	sig := ed25519.Sign(priv, eph)
	if err := stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                 chatID,
				TargetAppId:            targetAppID,
				PeerPublicEphemeralKey: eph,
				Signature:              sig,
			},
		},
	}); err != nil {
		t.Fatalf("send start chat: %v", err)
	}
}

func expectConnectAck(t *testing.T, stream approuterpb.AppRouter_OpenClient) {
	t.Helper()
	frame := recvFrame(t, stream)
	if _, ok := frame.Body.(*approuterpb.AppFrame_ConnectAck); !ok {
		t.Fatalf("expected ConnectAck, got %T", frame.Body)
	}
}

func expectStartChatAck(t *testing.T, stream approuterpb.AppRouter_OpenClient, chatID string) {
	t.Helper()
	frame := recvFrame(t, stream)
	body, ok := frame.Body.(*approuterpb.AppFrame_StartChatAck)
	if !ok {
		t.Fatalf("expected StartChatAck, got %T", frame.Body)
	}
	if body.StartChatAck.ChatId != chatID {
		t.Fatalf("expected chat %s, got %s", chatID, body.StartChatAck.ChatId)
	}
}

func expectChatAck(t *testing.T, stream approuterpb.AppRouter_OpenClient, chatID string, seq uint64) {
	t.Helper()
	frame := recvFrame(t, stream)
	ack, ok := frame.Body.(*approuterpb.AppFrame_ChatMessageAck)
	if !ok {
		t.Fatalf("expected ChatMessageAck, got %T", frame.Body)
	}
	if ack.ChatMessageAck.ChatId != chatID || ack.ChatMessageAck.Sequence != seq {
		t.Fatalf("unexpected ack: %+v", ack.ChatMessageAck)
	}
}

func expectDeleteAck(t *testing.T, stream approuterpb.AppRouter_OpenClient, status string) {
	t.Helper()
	frame := recvFrame(t, stream)
	ack, ok := frame.Body.(*approuterpb.AppFrame_DeleteChatAck)
	if !ok {
		t.Fatalf("expected DeleteChatAck, got %T", frame.Body)
	}
	if ack.DeleteChatAck.Status != status {
		t.Fatalf("expected status %s, got %s", status, ack.DeleteChatAck.Status)
	}
}

func waitForStartChat(t *testing.T, stream approuterpb.AppRouter_OpenClient) *approuterpb.StartChat {
	t.Helper()
	for {
		frame := recvFrame(t, stream)
		if body, ok := frame.Body.(*approuterpb.AppFrame_StartChat); ok {
			return body.StartChat
		}
	}
}

func waitForChatMessage(t *testing.T, stream approuterpb.AppRouter_OpenClient) *approuterpb.ChatMessage {
	t.Helper()
	for {
		frame := recvFrame(t, stream)
		if body, ok := frame.Body.(*approuterpb.AppFrame_ChatMessage); ok {
			return body.ChatMessage
		}
	}
}

func recvFrame(t *testing.T, stream approuterpb.AppRouter_OpenClient) *approuterpb.AppFrame {
	t.Helper()
	frame, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv frame: %v", err)
	}
	return frame
}

func mustKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return pub, priv
}

func mustRandBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

type memoryKeystore struct {
	mu      sync.Mutex
	secrets map[string][]byte
}

func newMemoryKeystore() *memoryKeystore {
	return &memoryKeystore{
		secrets: make(map[string][]byte),
	}
}

func (m *memoryKeystore) Initialize(_ context.Context, _ string) error { return nil }
func (m *memoryKeystore) Unlock(_ context.Context, _ string) error     { return nil }

func (m *memoryKeystore) StoreSecret(_ context.Context, keyID string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[keyID] = append([]byte(nil), secret...)
	return nil
}

func (m *memoryKeystore) LoadSecret(_ context.Context, keyID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	secret, ok := m.secrets[keyID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), secret...), nil
}

func (m *memoryKeystore) DeleteSecret(_ context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, keyID)
	return nil
}

func (m *memoryKeystore) has(keyID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.secrets[keyID]
	return ok
}
