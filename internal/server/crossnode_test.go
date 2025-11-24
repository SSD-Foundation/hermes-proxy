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

	peerA := waitForStartChatOrError(t, streamA)
	if !bytes.Equal(peerA.LocalEphemeralPublicKey, ephB.Public) {
		t.Fatalf("node A expected peer key %x, got %x", ephB.Public, peerA.LocalEphemeralPublicKey)
	}
	peerB := waitForStartChatOrError(t, streamB)
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

	_ = waitForStartChatOrError(t, streamA)
	_ = waitForStartChatOrError(t, streamB)

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

func TestCrossNodeRekeyAndResumeHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	chatID := "cross-rekey-resume"
	ephA1 := mustEphemeral(t)
	ephB1 := mustEphemeral(t)

	sendStartChat(t, streamA, chatID, appBID, ephA1, appAPriv)
	expectStartChatAck(t, streamA, chatID)
	sendStartChat(t, streamB, chatID, appAID, ephB1, appBPriv)
	expectStartChatAck(t, streamB, chatID)

	_ = waitForStartChatOrError(t, streamA)
	_ = waitForStartChatOrError(t, streamB)

	initialA := waitForSecretVersion(t, nodeA.ks, chatID, 1)
	initialB := waitForSecretVersion(t, nodeB.ks, chatID, 1)

	payload := []byte("rekey-payload-01")
	if err := streamA.Send(&approuterpb.AppFrame{
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
	expectChatAck(t, streamA, chatID, 1)
	msgB := waitForChatMessage(t, streamB)
	if msgB.Sequence != 1 {
		t.Fatalf("expected seq 1 on receiver, got %d", msgB.Sequence)
	}

	ephA2 := mustEphemeral(t)
	ephB2 := mustEphemeral(t)
	sendStartChatRekey(t, streamA, chatID, appBID, ephA2, appAPriv, 2)
	expectStartChatAck(t, streamA, chatID)
	sendStartChatRekey(t, streamB, chatID, appAID, ephB2, appBPriv, 2)
	expectStartChatAck(t, streamB, chatID)

	peerA := waitForStartChatOrError(t, streamA)
	if peerA.KeyVersion != 2 || !peerA.Rekey {
		t.Fatalf("expected rekey start for node A with version 2, got version %d rekey=%v", peerA.KeyVersion, peerA.Rekey)
	}
	peerB := waitForStartChatOrError(t, streamB)
	if peerB.KeyVersion != 2 || !peerB.Rekey {
		t.Fatalf("expected rekey start for node B with version 2, got version %d rekey=%v", peerB.KeyVersion, peerB.Rekey)
	}

	finalA := waitForSecretVersion(t, nodeA.ks, chatID, 2)
	finalB := waitForSecretVersion(t, nodeB.ks, chatID, 2)
	if bytes.Equal(initialA.SendKey, finalA.SendKey) || bytes.Equal(initialB.SendKey, finalB.SendKey) {
		t.Fatalf("expected ratchet keys to change after rekey")
	}

	payload2 := []byte("rekey-payload-02")
	if err := streamA.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  payload2,
				Sequence: 1,
			},
		},
	}); err != nil {
		t.Fatalf("send post-rekey message: %v", err)
	}
	expectChatAck(t, streamA, chatID, 1)
	msgAfter := waitForChatMessage(t, streamB)
	if msgAfter.Sequence != 1 {
		t.Fatalf("expected seq 1 after rekey, got %d", msgAfter.Sequence)
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
}

func TestCrossNodeRekeyThrottleAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	nodeA := startMeshTestNode(t, "node-a")
	nodeB := startMeshTestNode(t, "node-b")
	defer nodeA.stop()
	defer nodeB.stop()

	// tighten rekey window/limit to force throttling quickly
	nodeA.router.rekeyLimit = 1
	nodeA.router.rekeyWindow = time.Minute
	nodeB.router.rekeyLimit = 1
	nodeB.router.rekeyWindow = time.Minute

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

	chatID := "cross-rekey-throttle"
	ephA1 := mustEphemeral(t)
	ephB1 := mustEphemeral(t)

	sendStartChat(t, streamA, chatID, appBID, ephA1, appAPriv)
	expectStartChatAck(t, streamA, chatID)
	sendStartChat(t, streamB, chatID, appAID, ephB1, appBPriv)
	expectStartChatAck(t, streamB, chatID)

	_ = waitForStartChatOrError(t, streamA)
	_ = waitForStartChatOrError(t, streamB)

	ephA2 := mustEphemeral(t)
	ephB2 := mustEphemeral(t)
	sendStartChatRekey(t, streamA, chatID, appBID, ephA2, appAPriv, 2)
	expectStartChatAck(t, streamA, chatID)
	sendStartChatRekey(t, streamA, chatID, appBID, mustEphemeral(t), appAPriv, 2)
	frame := recvFrame(t, streamA)
	if errBody, ok := frame.Body.(*approuterpb.AppFrame_Error); ok {
		if errBody.Error.Code != "REKEY_THROTTLED" {
			t.Fatalf("expected REKEY_THROTTLED, got %s", errBody.Error.Code)
		}
	} else {
		t.Fatalf("expected error frame after throttled rekey, got %T", frame.Body)
	}

	sendStartChatRekey(t, streamB, chatID, appAID, ephB2, appBPriv, 2)
	expectStartChatAck(t, streamB, chatID)
	_ = waitForStartChatOrError(t, streamA)
	_ = waitForStartChatOrError(t, streamB)
	_ = waitForSecretVersion(t, nodeA.ks, chatID, 2)

	payload := []byte("throttle-payload-1")
	if err := streamA.Send(&approuterpb.AppFrame{
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
	expectChatAck(t, streamA, chatID, 1)
	_ = waitForChatMessage(t, streamB)

	sendStartChatRekey(t, streamA, chatID, appBID, mustEphemeral(t), appAPriv, 2)
	frame = recvFrame(t, streamA)
	if errBody, ok := frame.Body.(*approuterpb.AppFrame_Error); ok {
		if errBody.Error.Code != "REPLAYED_KEY" {
			t.Fatalf("expected REPLAYED_KEY after applied rekey, got %s", errBody.Error.Code)
		}
	} else {
		t.Fatalf("expected error frame after replayed rekey, got %T", frame.Body)
	}

	if err := streamB.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  []byte("throttle-payload-2"),
				Sequence: 1,
			},
		},
	}); err != nil {
		t.Fatalf("send receiver message: %v", err)
	}
	expectChatAck(t, streamB, chatID, 1)
	_ = waitForChatMessage(t, streamA)

	if err := streamA.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_DeleteChat{
			DeleteChat: &approuterpb.DeleteChat{ChatId: chatID, Reason: "done"},
		},
	}); err != nil {
		t.Fatalf("send delete chat: %v", err)
	}
	expectDeleteAck(t, streamA, "deleted")
	expectDeleteAck(t, streamB, "deleted_by_peer")
}

func TestCrossNodeResumeFromKeystore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	nodeA := startMeshTestNode(t, "node-a")
	nodeB := startMeshTestNode(t, "node-b")
	defer nodeA.stop()
	defer nodeB.stop()

	appAPub, appAPriv := mustKeypair(t)
	appBPub, appBPriv := mustKeypair(t)
	appAID := appIdentityKey(appAPub)
	appBID := appIdentityKey(appBPub)

	ephA := mustEphemeral(t)
	ephB := mustEphemeral(t)

	chatID := "cross-resume"
	seedResumeRecordForLocal(t, nodeA.ks, chatID, appAPub, appBPub, ephA, ephB, 2, "hermes-chat-session", 2, 1)
	seedResumeRecordForLocal(t, nodeB.ks, chatID, appBPub, appAPub, ephB, ephA, 2, "hermes-chat-session", 1, 2)

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

	sendConnectFrame(t, streamA, nodeA.id, appAPub, appAPriv, nil)
	sendConnectFrame(t, streamB, nodeB.id, appBPub, appBPriv, nil)
	expectConnectAck(t, streamA)
	expectConnectAck(t, streamB)

	now = time.Now()
	nodeA.store.MergeApps(nodeB.store.Apps(), now)
	nodeB.store.MergeApps(nodeA.store.Apps(), now)

	sendStartChatCustom(t, streamA, chatID, appBID, ephA, appAPriv, "hermes-chat-session", 2)
	expectStartChatAck(t, streamA, chatID)
	sendStartChatCustom(t, streamB, chatID, appAID, ephB, appBPriv, "hermes-chat-session", 2)
	expectStartChatAck(t, streamB, chatID)

	_ = waitForStartChatOrError(t, streamA)
	_ = waitForStartChatOrError(t, streamB)

	nextA := uint64(3)
	nextB := uint64(2)

	if err := streamA.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  []byte("resume-payload-a"),
				Sequence: nextA,
			},
		},
	}); err != nil {
		t.Fatalf("send resume message A: %v", err)
	}
	expectChatAck(t, streamA, chatID, nextA)
	msgB := waitForChatMessage(t, streamB)
	if msgB.Sequence != nextA {
		t.Fatalf("expected seq %d for receiver, got %d", nextA, msgB.Sequence)
	}

	if err := streamB.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  []byte("resume-payload-b"),
				Sequence: nextB,
			},
		},
	}); err != nil {
		t.Fatalf("send resume message B: %v", err)
	}
	expectChatAck(t, streamB, chatID, nextB)
	msgA := waitForChatMessage(t, streamA)
	if msgA.Sequence != nextB {
		t.Fatalf("expected seq %d for sender A, got %d", nextB, msgA.Sequence)
	}

	recA := waitForSecretVersion(t, nodeA.ks, chatID, 2)
	recB := waitForSecretVersion(t, nodeB.ks, chatID, 2)
	if recA.SendCount != 3 || recA.RecvCount != 2 {
		t.Fatalf("unexpected counters on node A: send=%d recv=%d", recA.SendCount, recA.RecvCount)
	}
	if recB.SendCount != 2 || recB.RecvCount != 3 {
		t.Fatalf("unexpected counters on node B: send=%d recv=%d", recB.SendCount, recB.RecvCount)
	}

	if err := streamA.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_DeleteChat{
			DeleteChat: &approuterpb.DeleteChat{ChatId: chatID, Reason: "resume-finished"},
		},
	}); err != nil {
		t.Fatalf("send delete chat: %v", err)
	}
	expectDeleteAck(t, streamA, "deleted")
	expectDeleteAck(t, streamB, "deleted_by_peer")
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

func waitForStartChatOrError(t *testing.T, stream approuterpb.AppRouter_OpenClient) *approuterpb.StartChat {
	t.Helper()
	for {
		frame := recvFrame(t, stream)
		switch body := frame.Body.(type) {
		case *approuterpb.AppFrame_StartChat:
			return body.StartChat
		case *approuterpb.AppFrame_Error:
			t.Fatalf("unexpected error while waiting for StartChat: %s %s", body.Error.Code, body.Error.Message)
		}
	}
}

func waitForSecretVersion(t *testing.T, ks *memoryKeystore, chatID string, version uint32) keystore.ChatSecretRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ks.has(chatID) {
			rec, err := ks.LoadChatSecret(context.Background(), chatID)
			if err == nil && rec.KeyVersion == version {
				return rec
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("chat secret %s with version %d not found", chatID, version)
	return keystore.ChatSecretRecord{}
}
