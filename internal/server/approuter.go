package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	sendBufferSize     = 32
	minCiphertextBytes = 16
)

// AppRouterService implements the gRPC AppRouter contract.
type AppRouterService struct {
	approuterpb.UnimplementedAppRouterServer
	log      *zap.Logger
	registry registry.ChatRegistry
	keystore keystore.KeyBackend

	mu       sync.Mutex
	sessions map[string]*appSession
	chats    map[string]*tieline
}

// NewAppRouterService wires dependencies for the gRPC handler.
func NewAppRouterService(log *zap.Logger, reg registry.ChatRegistry, ks keystore.KeyBackend) *AppRouterService {
	if reg == nil {
		reg = registry.NewInMemory(0)
	}
	return &AppRouterService{
		log:      log,
		registry: reg,
		keystore: ks,
		sessions: make(map[string]*appSession),
		chats:    make(map[string]*tieline),
	}
}

// Open handles the bidirectional AppRouter stream.
func (s *AppRouterService) Open(stream approuterpb.AppRouter_OpenServer) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return nil
		}
		return status.Errorf(codes.InvalidArgument, "read connect frame: %v", err)
	}

	connect := first.GetConnect()
	if connect == nil {
		return status.Error(codes.InvalidArgument, "first frame must be Connect")
	}

	session, err := s.handleConnect(ctx, connect)
	if err != nil {
		return err
	}
	defer s.cleanupSession(session)

	go s.sender(stream, session)

	if err := s.pushFrame(session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ConnectAck{
			ConnectAck: &approuterpb.ConnectAck{AssignedSessionId: session.id},
		},
	}); err != nil {
		return err
	}

	for {
		frame, recvErr := stream.Recv()
		if recvErr != nil {
			if errors.Is(recvErr, io.EOF) || errors.Is(recvErr, context.Canceled) {
				return nil
			}
			s.log.Warn("stream recv failed", zap.Error(recvErr))
			return recvErr
		}

		if err := s.routeFrame(session, frame); err != nil {
			var rerr *routeError
			if errors.As(err, &rerr) {
				_ = s.pushFrame(session, &approuterpb.AppFrame{
					Body: &approuterpb.AppFrame_Error{
						Error: &approuterpb.Error{Code: rerr.code, Message: rerr.msg},
					},
				})
				if rerr.fatal {
					return status.Error(codes.PermissionDenied, rerr.msg)
				}
				continue
			}
			return err
		}
	}
}

func (s *AppRouterService) handleConnect(parentCtx context.Context, connect *approuterpb.Connect) (*appSession, error) {
	if len(connect.AppPublicKey) != ed25519.PublicKeySize {
		return nil, status.Error(codes.Unauthenticated, "identity key must be ed25519 public key")
	}
	if len(connect.Signature) == 0 {
		return nil, status.Error(codes.Unauthenticated, "connect signature required")
	}
	payload := connectSignaturePayload(connect)
	if !ed25519.Verify(ed25519.PublicKey(connect.AppPublicKey), payload, connect.Signature) {
		return nil, status.Error(codes.Unauthenticated, "connect signature invalid")
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate session id: %v", err)
	}

	ctx, cancel := context.WithCancel(parentCtx)
	session := &appSession{
		id:           sessionID,
		appPublicKey: append([]byte(nil), connect.AppPublicKey...),
		metadata:     connect.Metadata,
		sendCh:       make(chan *approuterpb.AppFrame, sendBufferSize),
		ctx:          ctx,
		cancel:       cancel,
		connectedAt:  time.Now(),
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	s.log.Info("app connected", zap.String("session_id", sessionID), zap.Any("metadata", connect.Metadata))
	return session, nil
}

func (s *AppRouterService) routeFrame(session *appSession, frame *approuterpb.AppFrame) error {
	switch body := frame.Body.(type) {
	case *approuterpb.AppFrame_StartChat:
		return s.handleStartChat(session, body.StartChat)
	case *approuterpb.AppFrame_ChatMessage:
		return s.handleChatMessage(session, body.ChatMessage)
	case *approuterpb.AppFrame_DeleteChat:
		return s.handleDeleteChat(session, body.DeleteChat)
	case *approuterpb.AppFrame_Heartbeat:
		return s.handleHeartbeat(session, body.Heartbeat)
	case *approuterpb.AppFrame_Connect:
		return &routeError{code: "INVALID_FRAME", msg: "connect already completed", fatal: true}
	default:
		return &routeError{code: "INVALID_FRAME", msg: "unsupported frame"}
	}
}

func (s *AppRouterService) handleStartChat(session *appSession, start *approuterpb.StartChat) error {
	if start == nil || start.ChatId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}
	if len(start.PeerPublicEphemeralKey) == 0 {
		return &routeError{code: "INVALID_FRAME", msg: "ephemeral key required"}
	}
	if len(start.Signature) == 0 || !ed25519.Verify(session.appPublicKey, start.PeerPublicEphemeralKey, start.Signature) {
		return &routeError{code: "AUTH_FAILED", msg: "start chat signature invalid"}
	}

	participant := &chatParticipant{
		session:      session,
		ephemeralKey: append([]byte(nil), start.PeerPublicEphemeralKey...),
	}

	var notifications []peerNotification
	var combinedKeys [][]byte

	s.mu.Lock()
	tl, ok := s.chats[start.ChatId]
	if !ok {
		tl = newTieline(start.ChatId)
		s.chats[start.ChatId] = tl
		_ = s.registry.Register(registry.ChatSession{
			ChatID:    start.ChatId,
			CreatedAt: time.Now(),
			Metadata:  start.Metadata,
		})
	}

	if err := tl.addParticipant(participant); err != nil {
		s.mu.Unlock()
		return &routeError{code: "INVALID_FRAME", msg: err.Error()}
	}

	if tl.ready() {
		for sid, p := range tl.participants {
			peer := tl.peer(sid)
			if peer == nil {
				continue
			}
			notifications = append(notifications, peerNotification{
				target:  p.session,
				chatID:  tl.id,
				peerKey: append([]byte(nil), peer.ephemeralKey...),
			})
		}
		for _, p := range tl.participants {
			combinedKeys = append(combinedKeys, append([]byte(nil), p.ephemeralKey...))
		}
	}
	s.mu.Unlock()

	if err := s.pushFrame(session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChatAck{
			StartChatAck: &approuterpb.StartChatAck{ChatId: start.ChatId},
		},
	}); err != nil {
		return err
	}

	if len(notifications) > 0 {
		for _, n := range notifications {
			_ = s.pushFrame(n.target, &approuterpb.AppFrame{
				Body: &approuterpb.AppFrame_StartChat{
					StartChat: &approuterpb.StartChat{
						ChatId:                 n.chatID,
						PeerPublicEphemeralKey: n.peerKey,
					},
				},
			})
		}
		s.persistChatSecret(start.ChatId, combinedKeys)
	}

	return nil
}

func (s *AppRouterService) handleChatMessage(session *appSession, msg *approuterpb.ChatMessage) error {
	if msg == nil || msg.ChatId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}
	if len(msg.Payload) < minCiphertextBytes {
		return &routeError{code: "INVALID_FRAME", msg: "ciphertext envelope too small"}
	}

	var peer *chatParticipant
	expected := uint64(1)

	s.mu.Lock()
	tl, ok := s.chats[msg.ChatId]
	if !ok {
		s.mu.Unlock()
		return &routeError{code: "CHAT_NOT_FOUND", msg: "chat not found"}
	}

	sender, ok := tl.participants[session.id]
	if !ok {
		s.mu.Unlock()
		return &routeError{code: "CHAT_NOT_FOUND", msg: "sender not registered in chat"}
	}

	peer = tl.peer(session.id)
	if peer == nil {
		s.mu.Unlock()
		return &routeError{code: "CHAT_NOT_READY", msg: "chat not ready"}
	}

	if sender.nextSeq > 0 {
		expected = sender.nextSeq + 1
	} else if msg.Sequence == 0 {
		expected = 0
	}

	if msg.Sequence != expected {
		s.mu.Unlock()
		return &routeError{code: "BAD_SEQUENCE", msg: fmt.Sprintf("expected sequence %d", expected)}
	}

	sender.nextSeq = msg.Sequence
	s.mu.Unlock()

	if err := s.pushFrame(session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessageAck{
			ChatMessageAck: &approuterpb.ChatMessageAck{
				ChatId:   msg.ChatId,
				Sequence: msg.Sequence,
			},
		},
	}); err != nil {
		return err
	}

	forward := &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   msg.ChatId,
				Payload:  append([]byte(nil), msg.Payload...),
				Sequence: msg.Sequence,
			},
		},
	}
	return s.pushFrame(peer.session, forward)
}

func (s *AppRouterService) handleDeleteChat(session *appSession, del *approuterpb.DeleteChat) error {
	if del == nil || del.ChatId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}

	var sessions []*appSession

	s.mu.Lock()
	if tl, ok := s.chats[del.ChatId]; ok {
		for _, p := range tl.participants {
			sessions = append(sessions, p.session)
		}
		delete(s.chats, del.ChatId)
	}
	s.mu.Unlock()

	if len(sessions) == 0 {
		return &routeError{code: "CHAT_NOT_FOUND", msg: "chat not found"}
	}

	_ = s.registry.Delete(del.ChatId)
	s.eraseSecret(del.ChatId)

	for _, target := range sessions {
		statusMsg := "deleted"
		if target.id != session.id {
			statusMsg = "deleted_by_peer"
		}
		_ = s.pushFrame(target, &approuterpb.AppFrame{
			Body: &approuterpb.AppFrame_DeleteChatAck{
				DeleteChatAck: &approuterpb.DeleteChatAck{
					ChatId: del.ChatId,
					Status: statusMsg,
				},
			},
		})
	}

	return nil
}

func (s *AppRouterService) handleHeartbeat(session *appSession, hb *approuterpb.Heartbeat) error {
	if hb == nil {
		return nil
	}
	return s.pushFrame(session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_Heartbeat{
			Heartbeat: hb,
		},
	})
}

func (s *AppRouterService) sender(stream approuterpb.AppRouter_OpenServer, session *appSession) {
	for {
		select {
		case <-session.ctx.Done():
			return
		case frame, ok := <-session.sendCh:
			if !ok {
				return
			}
			if err := stream.Send(frame); err != nil {
				s.log.Warn("stream send failed", zap.Error(err), zap.String("session_id", session.id))
				session.cancel()
				return
			}
		}
	}
}

func (s *AppRouterService) pushFrame(session *appSession, frame *approuterpb.AppFrame) error {
	select {
	case <-session.ctx.Done():
		return session.ctx.Err()
	case session.sendCh <- frame:
		return nil
	default:
		session.cancel()
		return &routeError{code: "BACKPRESSURE", msg: "session send buffer full", fatal: true}
	}
}

func (s *AppRouterService) cleanupSession(session *appSession) {
	session.cancel()

	s.mu.Lock()
	delete(s.sessions, session.id)
	for chatID, tl := range s.chats {
		if _, ok := tl.participants[session.id]; ok {
			tl.removeParticipant(session.id)
			if tl.isEmpty() {
				delete(s.chats, chatID)
				_ = s.registry.Delete(chatID)
				s.eraseSecret(chatID)
			}
		}
	}
	close(session.sendCh)
	s.mu.Unlock()

	s.log.Info("app disconnected", zap.String("session_id", session.id))
}

func (s *AppRouterService) persistChatSecret(chatID string, keys [][]byte) {
	if s.keystore == nil || len(keys) == 0 {
		return
	}
	combined := bytes.Join(keys, []byte(":"))
	if err := s.keystore.StoreSecret(context.Background(), chatID, combined); err != nil {
		s.log.Warn("persist chat secret", zap.Error(err), zap.String("chat_id", chatID))
	}
}

func (s *AppRouterService) eraseSecret(chatID string) {
	if s.keystore == nil {
		return
	}
	if err := s.keystore.DeleteSecret(context.Background(), chatID); err != nil {
		s.log.Warn("erase chat secret", zap.Error(err), zap.String("chat_id", chatID))
	}
}

func connectSignaturePayload(connect *approuterpb.Connect) []byte {
	if connect == nil {
		return nil
	}
	buf := bytes.Buffer{}
	buf.WriteString(connect.NodeId)

	keys := make([]string, 0, len(connect.Metadata))
	for k := range connect.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteString(connect.Metadata[k])
	}
	return buf.Bytes()
}

func generateSessionID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// appSession tracks a connected app stream.
type appSession struct {
	id           string
	appPublicKey ed25519.PublicKey
	metadata     map[string]string
	sendCh       chan *approuterpb.AppFrame
	ctx          context.Context
	cancel       context.CancelFunc
	connectedAt  time.Time
}

// chatParticipant wraps per-chat sender state.
type chatParticipant struct {
	session      *appSession
	ephemeralKey []byte
	nextSeq      uint64
}

type peerNotification struct {
	target  *appSession
	chatID  string
	peerKey []byte
}

// routeError maps application-level validation to error frames.
type routeError struct {
	code  string
	msg   string
	fatal bool
}

func (e *routeError) Error() string {
	return e.msg
}

// tieline stores chat participants for in-memory routing.
type tieline struct {
	id           string
	participants map[string]*chatParticipant
}

func newTieline(id string) *tieline {
	return &tieline{
		id:           id,
		participants: make(map[string]*chatParticipant),
	}
}

func (t *tieline) addParticipant(p *chatParticipant) error {
	if len(t.participants) >= 2 {
		return errors.New("chat already has two participants")
	}
	if _, ok := t.participants[p.session.id]; ok {
		return errors.New("participant already registered")
	}
	t.participants[p.session.id] = p
	return nil
}

func (t *tieline) removeParticipant(sessionID string) {
	delete(t.participants, sessionID)
}

func (t *tieline) peer(sessionID string) *chatParticipant {
	for sid, p := range t.participants {
		if sid != sessionID {
			return p
		}
	}
	return nil
}

func (t *tieline) ready() bool {
	return len(t.participants) == 2
}

func (t *tieline) isEmpty() bool {
	return len(t.participants) == 0
}
