package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/crypto/pfs"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const minPayloadLen = 16

type appConfig struct {
	nodeAddr      string
	nodeID        string
	chatID        string
	role          string
	target        string
	targetNode    string
	payload       []byte
	timeout       time.Duration
	startDelay    time.Duration
	identitySeed  string
	peerSeed      string
	messages      int
	keyVersion    uint32
	rekey         bool
	rekeyVersion  uint32
	postRestart   int
	expectRestart bool
	maxRestarts   int
	appPub        ed25519.PublicKey
	appPriv       ed25519.PrivateKey
}

type chatState struct {
	currentVersion     uint32
	rekeyVersion       uint32
	currentEphemeral   pfs.KeyPair
	pendingEphemeral   pfs.KeyPair
	nextSeq            uint64
	rekeyComplete      bool
	rekeySent          bool
	prePhaseDone       bool
	postRestart        bool
	sentPre            int
	sentPost           int
	receivedPre        int
	receivedPost       int
	inFlight           bool
	deleteSent         bool
	restartReadyLogged bool
}

func main() {
	cfg := parseConfig()
	if err := run(cfg); err != nil {
		log.Fatalf("mock app failed: %v", err)
	}
	log.Printf("mock app role %s completed chat %s", cfg.role, cfg.chatID)
}

func parseConfig() appConfig {
	var cfg appConfig
	var payload string
	var identitySeed string
	var peerSeed string
	var messages int
	var keyVersion int
	var rekeyVersion int
	flag.StringVar(&cfg.nodeAddr, "node", "127.0.0.1:50051", "gRPC address for the node")
	flag.StringVar(&cfg.nodeID, "node-id", "hermes-dev", "Node ID used in Connect signatures")
	flag.StringVar(&cfg.chatID, "chat-id", "integration-chat", "Chat identifier to join")
	flag.StringVar(&cfg.role, "role", "sender", "Role for this app (sender|receiver)")
	flag.StringVar(&cfg.target, "target-app", "", "Target app identity to chat with")
	flag.StringVar(&cfg.targetNode, "target-node", "", "Optional target node hint")
	flag.StringVar(&identitySeed, "identity-seed", "", "Optional seed for deterministic identity generation")
	flag.StringVar(&peerSeed, "peer-seed", "", "Optional seed for peer identity when target-app is empty")
	flag.StringVar(&payload, "payload", "integration-payload-012345", "Ciphertext payload to relay")
	flag.IntVar(&messages, "messages", 2, "Number of messages to send before teardown (sender only)")
	flag.IntVar(&keyVersion, "key-version", 1, "Key version to advertise on StartChat")
	flag.DurationVar(&cfg.startDelay, "start-delay", 0, "Optional delay before sending StartChat")
	flag.BoolVar(&cfg.rekey, "rekey", false, "Mark StartChat as a rekey attempt (requires higher key version)")
	flag.IntVar(&rekeyVersion, "rekey-version", 0, "Optional key version to rekey to after handshake")
	flag.IntVar(&cfg.postRestart, "post-restart-messages", 0, "Messages to send after restart/resume (sender only)")
	flag.BoolVar(&cfg.expectRestart, "expect-restart", false, "Attempt to resume the chat if the stream drops")
	flag.IntVar(&cfg.maxRestarts, "max-restarts", 1, "Maximum restart/resume attempts when expect-restart is set")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "Overall timeout for the chat flow")
	flag.Parse()

	switch cfg.role {
	case "sender", "receiver":
	default:
		log.Fatalf("unsupported role %s (expected sender or receiver)", cfg.role)
	}

	cfg.identitySeed = identitySeed
	cfg.peerSeed = peerSeed
	if messages <= 0 {
		messages = 1
	}
	cfg.messages = messages
	if keyVersion <= 0 {
		keyVersion = 1
	}
	cfg.keyVersion = uint32(keyVersion)
	if rekeyVersion <= 0 {
		rekeyVersion = keyVersion
	}
	if cfg.rekey && rekeyVersion <= keyVersion {
		rekeyVersion = keyVersion + 1
	}
	cfg.rekeyVersion = uint32(rekeyVersion)

	if cfg.target == "" {
		if cfg.identitySeed == "" {
			cfg.identitySeed = defaultSeed(cfg.role)
		}
		if cfg.peerSeed == "" {
			cfg.peerSeed = defaultSeed(peerRole(cfg.role))
		}
		cfg.target = deriveAppIDFromSeed(cfg.peerSeed)
	}

	cfg.payload = []byte(payload)
	for len(cfg.payload) < minPayloadLen {
		cfg.payload = append(cfg.payload, '0')
	}

	if cfg.maxRestarts <= 0 {
		cfg.maxRestarts = 1
	}
	return cfg
}

func ensureIdentity(cfg *appConfig) error {
	if cfg.appPriv != nil {
		return nil
	}
	if cfg.identitySeed != "" {
		cfg.appPub, cfg.appPriv = deriveKey(cfg.identitySeed)
		return nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	cfg.appPub = pub
	cfg.appPriv = priv
	return nil
}

func newChatState(cfg appConfig) (*chatState, error) {
	eph, err := pfs.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}

	return &chatState{
		currentVersion:   cfg.keyVersion,
		rekeyVersion:     cfg.rekeyVersion,
		currentEphemeral: eph,
		nextSeq:          1,
		rekeyComplete:    cfg.rekeyVersion <= cfg.keyVersion,
	}, nil
}

func run(cfg appConfig) error {
	if err := ensureIdentity(&cfg); err != nil {
		return err
	}
	state, err := newChatState(cfg)
	if err != nil {
		return err
	}

	attempts := 0
	for {
		needsRestart, err := connectAndRun(cfg, state)
		if err != nil {
			if cfg.expectRestart && state.prePhaseDone && attempts < cfg.maxRestarts {
				attempts++
				state.postRestart = true
				state.prePhaseDone = true
				state.inFlight = false
				state.rekeySent = false
				log.Printf("resume attempt failed, retrying (%d/%d): %v", attempts, cfg.maxRestarts, err)
				time.Sleep(3 * time.Second)
				continue
			}
			return err
		}
		if !needsRestart {
			return nil
		}

		attempts++
		if !cfg.expectRestart || attempts > cfg.maxRestarts {
			return fmt.Errorf("stream closed before completion (attempts=%d)", attempts)
		}
		state.postRestart = true
		state.prePhaseDone = true
		state.inFlight = false
		state.rekeySent = false
		log.Printf("stream dropped, attempting resume (%d/%d)", attempts, cfg.maxRestarts)
		time.Sleep(3 * time.Second)
	}
}

func connectAndRun(cfg appConfig, state *chatState) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.nodeAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return false, fmt.Errorf("dial node: %w", err)
	}
	defer conn.Close()

	client := approuterpb.NewAppRouterClient(conn)
	stream, err := client.Open(ctx)
	if err != nil {
		return false, fmt.Errorf("open stream: %w", err)
	}

	if err := sendConnect(stream, cfg.nodeID, cfg.appPub, cfg.appPriv); err != nil {
		return false, err
	}
	if err := expectConnectAck(stream); err != nil {
		return false, err
	}
	log.Printf("connected as %s targeting %s (chat=%s, version=%d)", hex.EncodeToString(cfg.appPub), cfg.target, cfg.chatID, state.currentVersion)
	if cfg.startDelay > 0 {
		time.Sleep(cfg.startDelay)
	}
	if err := sendStartChat(stream, cfg.chatID, cfg.target, cfg.targetNode, state.currentEphemeral, cfg.appPriv, state.currentVersion, false); err != nil {
		return false, err
	}

	return driveChat(ctx, stream, cfg, state)
}

func driveChat(ctx context.Context, stream approuterpb.AppRouter_OpenClient, cfg appConfig, state *chatState) (bool, error) {
	gotAck := false
	gotPeer := false

	if cfg.expectRestart && !state.postRestart && cfg.role == "receiver" && currentRecvTarget(cfg, state) == 0 {
		state.prePhaseDone = true
	}

	for {
		if cfg.role == "sender" && gotAck && gotPeer && state.rekeyComplete {
			target, sentPtr := phaseTargets(cfg, state)
			if target == 0 && (state.postRestart || !cfg.expectRestart) && !state.deleteSent {
				if err := sendDelete(stream, cfg.chatID, "integration-finished"); err != nil {
					return false, err
				}
				log.Printf("sent delete (phase=%s)", phaseLabel(state))
				state.deleteSent = true
			} else if !state.inFlight && *sentPtr < target && !state.deleteSent {
				if err := sendChatMessage(stream, cfg.chatID, cfg.payload, state.nextSeq); err != nil {
					return false, err
				}
				log.Printf("sent chat seq %d (phase=%s)", state.nextSeq, phaseLabel(state))
				state.nextSeq++
				state.inFlight = true
			} else if *sentPtr >= target {
				if state.postRestart || !cfg.expectRestart {
					if !state.deleteSent {
						if err := sendDelete(stream, cfg.chatID, "integration-finished"); err != nil {
							return false, err
						}
						log.Printf("sent delete (phase=%s)", phaseLabel(state))
						state.deleteSent = true
					}
				} else {
					state.prePhaseDone = true
					markReadyForRestart(state, cfg)
				}
			}
		}

		frame, err := stream.Recv()
		if err != nil {
			if cfg.expectRestart && !state.postRestart && state.prePhaseDone {
				return true, nil
			}
			if ctx.Err() != nil {
				return false, fmt.Errorf("stream recv: %w", ctx.Err())
			}
			return false, fmt.Errorf("stream recv: %w", err)
		}

		switch body := frame.Body.(type) {
		case *approuterpb.AppFrame_StartChatAck:
			gotAck = true
			log.Printf("start chat ack received (version=%d, phase=%s)", state.currentVersion, phaseLabel(state))
		case *approuterpb.AppFrame_StartChat:
			gotPeer = true
			log.Printf("peer start chat (version=%d, rekey=%v, phase=%s)", body.StartChat.KeyVersion, body.StartChat.Rekey, phaseLabel(state))
			if body.StartChat.Rekey && body.StartChat.KeyVersion > state.currentVersion {
				state.currentVersion = body.StartChat.KeyVersion
				state.rekeyComplete = true
				state.rekeySent = false
				state.inFlight = false
				state.nextSeq = 1
				if len(state.pendingEphemeral.Public) > 0 {
					state.currentEphemeral = state.pendingEphemeral
					state.pendingEphemeral = pfs.KeyPair{}
				}
				log.Printf("rekey applied (version=%d)", state.currentVersion)
			}
		case *approuterpb.AppFrame_ChatMessageAck:
			if cfg.role == "sender" {
				sentPtr := currentSentCounter(state)
				*sentPtr++
				state.inFlight = false
				log.Printf("ack seq %d (phase=%s)", body.ChatMessageAck.Sequence, phaseLabel(state))
			}
		case *approuterpb.AppFrame_ChatMessage:
			if cfg.role == "receiver" {
				if !bytes.Equal(body.ChatMessage.Payload, cfg.payload) {
					return false, fmt.Errorf("received payload mismatch: %x vs %x", body.ChatMessage.Payload, cfg.payload)
				}
				recvPtr := currentRecvCounter(state)
				*recvPtr++
				log.Printf("received seq %d (phase=%s)", body.ChatMessage.Sequence, phaseLabel(state))
				target := currentRecvTarget(cfg, state)
				if cfg.expectRestart && !state.postRestart && *recvPtr >= target {
					state.prePhaseDone = true
					markReadyForRestart(state, cfg)
				}
			}
		case *approuterpb.AppFrame_DeleteChatAck:
			if err := validateDeleteStatus(body.DeleteChatAck.Status, cfg.role); err != nil {
				return false, err
			}
			return false, nil
		case *approuterpb.AppFrame_Error:
			return false, fmt.Errorf("error frame: %s %s", body.Error.Code, body.Error.Message)
		case *approuterpb.AppFrame_Heartbeat:
			continue
		}

		if shouldSendRekey(gotAck, gotPeer, state) {
			if err := sendRekeyStart(stream, cfg, state); err != nil {
				return false, err
			}
		}
	}
}

func phaseTargets(cfg appConfig, state *chatState) (int, *int) {
	if state.postRestart {
		return cfg.postRestart, &state.sentPost
	}
	return cfg.messages, &state.sentPre
}

func currentSentCounter(state *chatState) *int {
	if state.postRestart {
		return &state.sentPost
	}
	return &state.sentPre
}

func currentRecvCounter(state *chatState) *int {
	if state.postRestart {
		return &state.receivedPost
	}
	return &state.receivedPre
}

func currentRecvTarget(cfg appConfig, state *chatState) int {
	if state.postRestart {
		return cfg.postRestart
	}
	return cfg.messages
}

func validateDeleteStatus(status, role string) error {
	switch role {
	case "sender":
		switch status {
		case "deleted", "rekey_required", "ratchet_desync":
			return nil
		}
	case "receiver":
		switch status {
		case "deleted_by_peer", "expired", "ratchet_desync", "rekey_required", "route_closed", "route_unavailable":
			return nil
		}
	}
	return fmt.Errorf("unexpected delete status %s", status)
}

func shouldSendRekey(gotAck, gotPeer bool, state *chatState) bool {
	if state.rekeyComplete || state.rekeyVersion <= state.currentVersion || state.rekeySent {
		return false
	}
	return gotAck && gotPeer
}

func sendRekeyStart(stream approuterpb.AppRouter_OpenClient, cfg appConfig, state *chatState) error {
	eph, err := pfs.GenerateKeyPair(rand.Reader)
	if err != nil {
		return fmt.Errorf("rekey ephemeral key: %w", err)
	}
	state.pendingEphemeral = eph
	state.rekeySent = true
	state.rekeyComplete = false
	state.inFlight = false
	log.Printf("sending rekey start (version=%d)", state.rekeyVersion)
	return sendStartChat(stream, cfg.chatID, cfg.target, cfg.targetNode, eph, cfg.appPriv, state.rekeyVersion, true)
}

func phaseLabel(state *chatState) string {
	if state.postRestart {
		return "post-restart"
	}
	return "pre-restart"
}

func markReadyForRestart(state *chatState, cfg appConfig) {
	if cfg.expectRestart && !state.restartReadyLogged {
		state.restartReadyLogged = true
		log.Printf("ready for restart (role=%s, chat=%s)", cfg.role, cfg.chatID)
	}
}

func sendConnect(stream approuterpb.AppRouter_OpenClient, nodeID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	sig := ed25519.Sign(priv, []byte(nodeID))
	return stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_Connect{
			Connect: &approuterpb.Connect{
				AppPublicKey: pub,
				Signature:    sig,
				NodeId:       nodeID,
			},
		},
	})
}

func expectConnectAck(stream approuterpb.AppRouter_OpenClient) error {
	frame, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv connect ack: %w", err)
	}
	if _, ok := frame.Body.(*approuterpb.AppFrame_ConnectAck); !ok {
		return fmt.Errorf("expected ConnectAck, got %T", frame.Body)
	}
	return nil
}

func sendStartChat(stream approuterpb.AppRouter_OpenClient, chatID, target, targetNode string, eph pfs.KeyPair, priv ed25519.PrivateKey, keyVersion uint32, rekey bool) error {
	appID := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	info := "hermes-chat-session"
	if keyVersion == 0 {
		keyVersion = 1
	}
	payload := startPayload(chatID, appID, target, eph.Public, nil, info, keyVersion, rekey)
	sig := ed25519.Sign(priv, payload)
	return stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                   chatID,
				TargetAppId:              target,
				TargetNodeHint:           targetNode,
				LocalEphemeralPublicKey:  eph.Public,
				LocalEphemeralPrivateKey: eph.Private,
				Signature:                sig,
				KeyVersion:               keyVersion,
				HkdfInfo:                 info,
				Rekey:                    rekey,
			},
		},
	})
}

func sendChatMessage(stream approuterpb.AppRouter_OpenClient, chatID string, payload []byte, seq uint64) error {
	return stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  payload,
				Sequence: seq,
			},
		},
	})
}

func sendDelete(stream approuterpb.AppRouter_OpenClient, chatID, reason string) error {
	return stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_DeleteChat{
			DeleteChat: &approuterpb.DeleteChat{ChatId: chatID, Reason: reason},
		},
	})
}

func startPayload(chatID, sourceAppID, targetAppID string, public, hkdfSalt []byte, hkdfInfo string, version uint32, rekey bool) []byte {
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], version)

	buf := bytes.Buffer{}
	buf.WriteString(chatID)
	buf.WriteByte(0)
	buf.WriteString(sourceAppID)
	buf.WriteByte(0)
	buf.WriteString(targetAppID)
	buf.WriteByte(0)
	buf.Write(public)
	buf.WriteByte(0)
	buf.Write(hkdfSalt)
	buf.WriteByte(0)
	buf.WriteString(hkdfInfo)
	buf.WriteByte(0)
	buf.Write(ver[:])
	if rekey {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func deriveKey(seed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	sum := sha256.Sum256([]byte(seed))
	priv := ed25519.NewKeyFromSeed(sum[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func deriveAppIDFromSeed(seed string) string {
	pub, _ := deriveKey(seed)
	return hex.EncodeToString(pub)
}

func defaultSeed(role string) string {
	if role == "receiver" {
		return "mockapp-receiver"
	}
	return "mockapp-sender"
}

func peerRole(role string) string {
	if role == "receiver" {
		return "sender"
	}
	return "receiver"
}
