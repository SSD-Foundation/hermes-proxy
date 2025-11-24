package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const minPayloadLen = 16

type appConfig struct {
	nodeAddr     string
	nodeID       string
	chatID       string
	role         string
	target       string
	payload      []byte
	timeout      time.Duration
	identitySeed string
	peerSeed     string
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
	flag.StringVar(&cfg.nodeAddr, "node", "127.0.0.1:50051", "gRPC address for the node")
	flag.StringVar(&cfg.nodeID, "node-id", "hermes-dev", "Node ID used in Connect signatures")
	flag.StringVar(&cfg.chatID, "chat-id", "integration-chat", "Chat identifier to join")
	flag.StringVar(&cfg.role, "role", "sender", "Role for this app (sender|receiver)")
	flag.StringVar(&cfg.target, "target-app", "", "Target app identity to chat with")
	flag.StringVar(&identitySeed, "identity-seed", "", "Optional seed for deterministic identity generation")
	flag.StringVar(&peerSeed, "peer-seed", "", "Optional seed for peer identity when target-app is empty")
	flag.StringVar(&payload, "payload", "integration-payload-012345", "Ciphertext payload to relay")
	flag.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "Overall timeout for the chat flow")
	flag.Parse()

	switch cfg.role {
	case "sender", "receiver":
	default:
		log.Fatalf("unsupported role %s (expected sender or receiver)", cfg.role)
	}

	cfg.identitySeed = identitySeed
	cfg.peerSeed = peerSeed

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
	return cfg
}

func run(cfg appConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	conn, err := grpc.DialContext(ctx, cfg.nodeAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial node: %w", err)
	}
	defer conn.Close()

	client := approuterpb.NewAppRouterClient(conn)
	stream, err := client.Open(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	if cfg.identitySeed != "" {
		pub, priv = deriveKey(cfg.identitySeed)
	} else {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
	}
	if err := sendConnect(stream, cfg.nodeID, pub, priv); err != nil {
		return err
	}
	if err := expectConnectAck(stream); err != nil {
		return err
	}

	eph := make([]byte, 32)
	if _, err := rand.Read(eph); err != nil {
		return fmt.Errorf("ephemeral key: %w", err)
	}
	if err := sendStartChat(stream, cfg.chatID, cfg.target, eph, priv); err != nil {
		return err
	}

	return handleFrames(ctx, stream, cfg)
}

func handleFrames(ctx context.Context, stream approuterpb.AppRouter_OpenClient, cfg appConfig) error {
	var (
		gotAck       bool
		gotPeer      bool
		msgAck       bool
		sentMessage  bool
		sentDelete   bool
		gotDeleteAck bool
		receivedMsg  bool
	)

	for {
		frame, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("stream recv: %w", ctx.Err())
			}
			return fmt.Errorf("stream recv: %w", err)
		}

		switch body := frame.Body.(type) {
		case *approuterpb.AppFrame_StartChatAck:
			gotAck = true
		case *approuterpb.AppFrame_StartChat:
			gotPeer = true
		case *approuterpb.AppFrame_ChatMessageAck:
			msgAck = true
		case *approuterpb.AppFrame_ChatMessage:
			if cfg.role == "receiver" {
				if !bytes.Equal(body.ChatMessage.Payload, cfg.payload) {
					return fmt.Errorf("received payload mismatch: %x vs %x", body.ChatMessage.Payload, cfg.payload)
				}
				receivedMsg = true
			}
		case *approuterpb.AppFrame_DeleteChatAck:
			gotDeleteAck = true
			switch cfg.role {
			case "sender":
				if body.DeleteChatAck.Status != "deleted" {
					return fmt.Errorf("unexpected delete status %s", body.DeleteChatAck.Status)
				}
			case "receiver":
				if body.DeleteChatAck.Status != "deleted_by_peer" && body.DeleteChatAck.Status != "expired" {
					return fmt.Errorf("unexpected delete status %s", body.DeleteChatAck.Status)
				}
			}
		case *approuterpb.AppFrame_Error:
			return fmt.Errorf("error frame: %s %s", body.Error.Code, body.Error.Message)
		case *approuterpb.AppFrame_Heartbeat:
			continue
		}

		if cfg.role == "sender" && gotAck && gotPeer && !sentMessage {
			if err := sendChatMessage(stream, cfg.chatID, cfg.payload); err != nil {
				return err
			}
			sentMessage = true
		}

		if cfg.role == "sender" && sentMessage && msgAck && !sentDelete {
			if err := sendDelete(stream, cfg.chatID, "integration-finished"); err != nil {
				return err
			}
			sentDelete = true
		}

		if cfg.role == "sender" && gotDeleteAck {
			return nil
		}
		if cfg.role == "receiver" && receivedMsg && gotDeleteAck {
			return nil
		}
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

func sendStartChat(stream approuterpb.AppRouter_OpenClient, chatID, target string, eph []byte, priv ed25519.PrivateKey) error {
	sig := ed25519.Sign(priv, eph)
	return stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                 chatID,
				TargetAppId:            target,
				PeerPublicEphemeralKey: eph,
				Signature:              sig,
			},
		},
	})
}

func sendChatMessage(stream approuterpb.AppRouter_OpenClient, chatID string, payload []byte) error {
	return stream.Send(&approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   chatID,
				Payload:  payload,
				Sequence: 1,
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
