package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/crypto/pfs"
	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/mesh"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	sendBufferSize     = 32
	minCiphertextBytes = 16
	maxHKDFSaltSize    = 64
	maxHKDFInfoSize    = 256
	ratchetDesync      = "ratchet_desync"
	ratchetExpired     = "rekey_required"
)

var (
	errStaleKeyVersion = errors.New("stale key version")
	errHKDFMismatch    = errors.New("hkdf parameters mismatch")
	errRatchetMissing  = errors.New("ratchet state unavailable")
	errKeyExpired      = errors.New("chat key lifetime exceeded")
)

type ratchetDirection string

const (
	ratchetSend ratchetDirection = "send"
	ratchetRecv ratchetDirection = "recv"
)

// RouterOptions configures observability and lifecycle hooks.
type RouterOptions struct {
	Metrics              *routerMetrics
	SessionIdleTimeout   time.Duration
	ChatIdleTimeout      time.Duration
	HousekeepingInterval time.Duration
	NodeID               string
	Apps                 registry.AppRegistry
	MeshStore            *mesh.Store
	Routes               *mesh.RouteClientPool
	HKDFHash             string
	HKDFInfo             string
	MaxKeyLifetime       time.Duration
}

// AppRouterService implements the gRPC AppRouter contract.
type AppRouterService struct {
	approuterpb.UnimplementedAppRouterServer
	log       *zap.Logger
	registry  registry.ChatRegistry
	keystore  keystore.KeyBackend
	metrics   *routerMetrics
	mu        sync.Mutex
	sessions  map[string]*appSession
	byAppID   map[string]*appSession
	chats     map[string]*tieline
	houseOnce sync.Once

	nodeID         string
	hkdfHash       crypto.Hash
	hkdfInfo       string
	maxKeyLifetime time.Duration
	apps           registry.AppRegistry
	store          *mesh.Store
	routes         *mesh.RouteClientPool

	sessionIdleTimeout   time.Duration
	chatIdleTimeout      time.Duration
	housekeepingInterval time.Duration
}

// NewAppRouterService wires dependencies for the gRPC handler.
func NewAppRouterService(log *zap.Logger, reg registry.ChatRegistry, ks keystore.KeyBackend, opts RouterOptions) *AppRouterService {
	if log == nil {
		log = zap.NewNop()
	}
	if reg == nil {
		reg = registry.NewInMemory(0)
	}
	hash := hashFromName(opts.HKDFHash)
	if hash == 0 {
		hash = crypto.SHA256
	}
	info := opts.HKDFInfo
	if info == "" {
		info = "hermes-chat-session"
	}
	maxLifetime := opts.MaxKeyLifetime
	if maxLifetime <= 0 {
		maxLifetime = 24 * time.Hour
	}
	svc := &AppRouterService{
		log:                  log,
		registry:             reg,
		keystore:             ks,
		metrics:              opts.Metrics,
		sessions:             make(map[string]*appSession),
		byAppID:              make(map[string]*appSession),
		chats:                make(map[string]*tieline),
		sessionIdleTimeout:   opts.SessionIdleTimeout,
		chatIdleTimeout:      opts.ChatIdleTimeout,
		housekeepingInterval: opts.HousekeepingInterval,
		nodeID:               opts.NodeID,
		hkdfHash:             hash,
		hkdfInfo:             info,
		maxKeyLifetime:       maxLifetime,
		apps:                 opts.Apps,
		store:                opts.MeshStore,
		routes:               opts.Routes,
	}
	if svc.sessionIdleTimeout <= 0 {
		svc.sessionIdleTimeout = 5 * time.Minute
	}
	if svc.chatIdleTimeout <= 0 {
		svc.chatIdleTimeout = 15 * time.Minute
	}
	if svc.housekeepingInterval <= 0 {
		svc.housekeepingInterval = time.Minute
	}
	return svc
}

// StartHousekeeping launches periodic cleanup for idle chats.
func (s *AppRouterService) StartHousekeeping(ctx context.Context) {
	if s.chatIdleTimeout <= 0 || s.housekeepingInterval <= 0 {
		return
	}

	s.houseOnce.Do(func() {
		ticker := time.NewTicker(s.housekeepingInterval)
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.expireIdleChats(time.Now())
				}
			}
		}()
	})
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

	start := time.Now()
	session, err := s.handleConnect(ctx, connect)
	if err != nil {
		s.observe("connect", start, err)
		return err
	}
	s.observe("connect", start, nil)
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
		start := time.Now()
		frame, recvErr := stream.Recv()
		if recvErr != nil {
			if errors.Is(recvErr, io.EOF) || errors.Is(recvErr, context.Canceled) {
				return nil
			}
			s.log.Warn("stream recv failed", zap.Error(recvErr))
			return recvErr
		}

		op := metricOp(frame)
		if err := s.routeFrame(session, frame); err != nil {
			s.observe(op, start, err)
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
		s.observe(op, start, nil)
	}
}

func (s *AppRouterService) handleConnect(parentCtx context.Context, connect *approuterpb.Connect) (*appSession, error) {
	if len(connect.AppPublicKey) != ed25519.PublicKeySize {
		return nil, status.Error(codes.Unauthenticated, "identity key must be ed25519 public key")
	}
	if len(connect.Signature) == 0 {
		return nil, status.Error(codes.Unauthenticated, "connect signature required")
	}
	if s.nodeID != "" && connect.NodeId != "" && connect.NodeId != s.nodeID {
		return nil, status.Error(codes.PermissionDenied, "connect target node mismatch")
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
	now := time.Now()
	session := &appSession{
		id:           sessionID,
		appPublicKey: append([]byte(nil), connect.AppPublicKey...),
		metadata:     connect.Metadata,
		sendCh:       make(chan *approuterpb.AppFrame, sendBufferSize),
		ctx:          ctx,
		cancel:       cancel,
		connectedAt:  now,
		lastSeen:     now,
		appID:        appIdentityKey(connect.AppPublicKey),
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.byAppID[session.appID] = session
	s.mu.Unlock()
	s.incSession()

	if s.apps != nil {
		_ = s.apps.Register(registry.AppPresence{
			AppID:       session.appID,
			NodeID:      s.nodeID,
			SessionID:   sessionID,
			Metadata:    connect.Metadata,
			ConnectedAt: now,
		})
		s.syncLocalApps(now)
	}

	s.log.Info("app connected", zap.String("session_id", sessionID), zap.Any("metadata", connect.Metadata))
	return session, nil
}

func (s *AppRouterService) routeFrame(session *appSession, frame *approuterpb.AppFrame) error {
	s.touchSession(session)
	switch body := frame.Body.(type) {
	case *approuterpb.AppFrame_StartChat:
		return s.handleStartChat(session, body.StartChat)
	case *approuterpb.AppFrame_ChatMessage:
		return s.handleChatMessage(session, body.ChatMessage)
	case *approuterpb.AppFrame_DeleteChat:
		return s.handleDeleteChat(session, body.DeleteChat)
	case *approuterpb.AppFrame_Heartbeat:
		return s.handleHeartbeat(session, body.Heartbeat)
	case *approuterpb.AppFrame_FindApp:
		return s.handleFindApp(session, body.FindApp)
	case *approuterpb.AppFrame_Connect:
		return &routeError{code: "INVALID_FRAME", msg: "connect already completed", fatal: true}
	default:
		return &routeError{code: "INVALID_FRAME", msg: "unsupported frame"}
	}
}

func (s *AppRouterService) handleStartChat(session *appSession, start *approuterpb.StartChat) error {
	start, err := s.normalizeStartChat(session, start)
	if err != nil {
		return err
	}

	routeNode, localRoute, err := s.resolveRoute(start.TargetAppId, start.TargetNodeHint)
	if err != nil {
		return &routeError{code: "TARGET_NOT_FOUND", msg: err.Error()}
	}

	participant := &chatParticipant{
		session: session,
		appID:   session.appID,
		keys: keyMaterial{
			public:     cloneBytes(start.LocalEphemeralPublicKey),
			private:    cloneBytes(start.LocalEphemeralPrivateKey),
			signature:  cloneBytes(start.Signature),
			keyVersion: start.KeyVersion,
			hkdfSalt:   cloneBytes(start.HkdfSalt),
			hkdfInfo:   start.HkdfInfo,
			rekey:      start.Rekey,
		},
	}

	var notifications []peerNotification
	var remoteReady bool
	var remoteNode string

	now := time.Now()
	s.mu.Lock()
	tl, ok := s.chats[start.ChatId]
	if !ok {
		tl = newTieline(start.ChatId)
		s.chats[start.ChatId] = tl
		_ = s.registry.Register(registry.ChatSession{
			ChatID:    start.ChatId,
			CreatedAt: now,
			Metadata:  cloneMetadata(start.Metadata),
		})
		s.incChat()
	}
	if tl.metadata == nil && len(start.Metadata) > 0 {
		tl.metadata = cloneMetadata(start.Metadata)
	}

	if err := tl.prepareVersion(participant.keys.keyVersion, participant.keys.hkdfInfo, participant.keys.hkdfSalt); err != nil {
		s.mu.Unlock()
		code := "KEY_MISMATCH"
		if errors.Is(err, errStaleKeyVersion) {
			code = "REPLAYED_KEY"
		}
		return &routeError{code: code, msg: err.Error()}
	}
	if err := tl.addOrUpdateParticipant(participant); err != nil {
		s.mu.Unlock()
		code := "INVALID_FRAME"
		if errors.Is(err, errStaleKeyVersion) {
			code = "REPLAYED_KEY"
		} else if errors.Is(err, errHKDFMismatch) {
			code = "KEY_MISMATCH"
		}
		return &routeError{code: code, msg: err.Error()}
	}
	tl.markActive()

	if localRoute {
		if tl.readyLocal() {
			for sid, p := range tl.participants {
				peer := tl.peer(sid)
				if peer == nil {
					continue
				}
				notifications = append(notifications, peerNotification{
					target:     p.session,
					chatID:     tl.id,
					peerPublic: cloneBytes(peer.keys.public),
					signature:  cloneBytes(peer.keys.signature),
					keyVersion: tl.keyVersion,
					hkdfSalt:   cloneBytes(tl.hkdfSalt),
					hkdfInfo:   tl.hkdfInfo,
					rekey:      peer.keys.rekey,
				})
			}
		}
	} else {
		remoteNode = routeNode
		if tl.remote == nil {
			tl.remote = &remotePeer{
				nodeID:      routeNode,
				appID:       start.TargetAppId,
				pendingAcks: make(map[uint64]*appSession),
			}
		} else {
			if tl.remote.pendingAcks == nil {
				tl.remote.pendingAcks = make(map[uint64]*appSession)
			}
			if tl.remote.nodeID == "" {
				tl.remote.nodeID = routeNode
			}
		}
		remoteReady = tl.readyRemote()
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
						ChatId:                  n.chatID,
						LocalEphemeralPublicKey: n.peerPublic,
						Signature:               n.signature,
						KeyVersion:              n.keyVersion,
						HkdfSalt:                cloneBytes(n.hkdfSalt),
						HkdfInfo:                n.hkdfInfo,
						Rekey:                   n.rekey,
					},
				},
			})
		}
		if err := s.tryDeriveChatSecret(start.ChatId); err != nil {
			return &routeError{code: "DERIVATION_FAILED", msg: err.Error()}
		}
	}

	if remoteReady {
		s.notifyRemoteReady(start.ChatId)
	}

	if remoteNode != "" {
		if err := s.sendRemoteSetup(remoteNode, session, start); err != nil {
			return err
		}
	}

	return nil
}

func (s *AppRouterService) normalizeStartChat(session *appSession, start *approuterpb.StartChat) (*approuterpb.StartChat, error) {
	if start == nil || start.ChatId == "" {
		return nil, &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}
	if start.TargetAppId == "" {
		return nil, &routeError{code: "INVALID_FRAME", msg: "target app id required"}
	}
	if start.KeyVersion == 0 {
		start.KeyVersion = 1
	}
	if start.HkdfInfo == "" {
		start.HkdfInfo = s.hkdfInfo
	}
	if len(start.HkdfSalt) > maxHKDFSaltSize {
		return nil, &routeError{code: "INVALID_FRAME", msg: fmt.Sprintf("hkdf salt too large (%d bytes)", len(start.HkdfSalt))}
	}
	if len(start.HkdfInfo) > maxHKDFInfoSize {
		return nil, &routeError{code: "INVALID_FRAME", msg: fmt.Sprintf("hkdf info too large (%d bytes)", len(start.HkdfInfo))}
	}
	if len(start.LocalEphemeralPublicKey) != pfs.KeySize {
		return nil, &routeError{code: "INVALID_KEY", msg: fmt.Sprintf("ephemeral public key must be %d bytes", pfs.KeySize)}
	}
	if len(start.LocalEphemeralPrivateKey) != pfs.KeySize {
		return nil, &routeError{code: "INVALID_KEY", msg: fmt.Sprintf("ephemeral private key must be %d bytes", pfs.KeySize)}
	}
	if err := pfs.ValidatePublicKey(start.LocalEphemeralPublicKey); err != nil {
		return nil, &routeError{code: "INVALID_KEY", msg: err.Error()}
	}
	privKey, err := ecdh.X25519().NewPrivateKey(start.LocalEphemeralPrivateKey)
	if err != nil {
		return nil, &routeError{code: "INVALID_KEY", msg: "invalid ephemeral private key"}
	}
	if !bytes.Equal(privKey.PublicKey().Bytes(), start.LocalEphemeralPublicKey) {
		return nil, &routeError{code: "INVALID_KEY", msg: "ephemeral key pair mismatch"}
	}

	payload := handshakePayload(start.ChatId, session.appID, start.TargetAppId, start.LocalEphemeralPublicKey, start.HkdfSalt, start.HkdfInfo, start.KeyVersion, start.Rekey)
	if len(start.Signature) == 0 || !ed25519.Verify(session.appPublicKey, payload, start.Signature) {
		return nil, &routeError{code: "AUTH_FAILED", msg: "start chat signature invalid"}
	}
	return start, nil
}

func (s *AppRouterService) sendRemoteSetup(nodeID string, session *appSession, start *approuterpb.StartChat) error {
	if s.routes == nil {
		return &routeError{code: "ROUTE_UNAVAILABLE", msg: "mesh routing not configured"}
	}

	frame := &nodemeshpb.RouteFrame{
		CorrelationId: start.ChatId,
		Body: &nodemeshpb.RouteFrame_SetupTieline{
			SetupTieline: &nodemeshpb.SetupTieline{
				ChatId:             start.ChatId,
				SourceAppId:        session.appID,
				TargetAppId:        start.TargetAppId,
				SourceEphemeralKey: start.LocalEphemeralPublicKey,
				Signature:          start.Signature,
				Metadata:           cloneMetadata(start.Metadata),
				SourceNodeId:       s.nodeID,
				SourcePublicKey:    append([]byte(nil), session.appPublicKey...),
				KeyVersion:         start.KeyVersion,
				HkdfSalt:           cloneBytes(start.HkdfSalt),
				HkdfInfo:           start.HkdfInfo,
				Rekey:              start.Rekey,
			},
		},
	}

	if err := s.routes.Send(context.Background(), nodeID, frame); err != nil {
		return &routeError{code: "ROUTE_UNAVAILABLE", msg: fmt.Sprintf("route to node %s unavailable", nodeID)}
	}
	return nil
}

func (s *AppRouterService) notifyRemoteReady(chatID string) {
	s.mu.Lock()
	tl, ok := s.chats[chatID]
	if !ok || !tl.readyRemote() || tl.remote == nil || tl.remote.startNotified {
		s.mu.Unlock()
		return
	}
	var local *chatParticipant
	for _, p := range tl.participants {
		local = p
		break
	}
	if local == nil {
		s.mu.Unlock()
		return
	}
	peer := tl.remote
	peerKey := cloneBytes(peer.ephemeralKey)
	sig := cloneBytes(peer.signature)
	hkdfSalt := cloneBytes(tl.hkdfSalt)
	hkdfInfo := tl.hkdfInfo
	version := tl.keyVersion
	rekey := peer.rekey
	tl.remote.startNotified = true
	s.mu.Unlock()

	_ = s.pushFrame(local.session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                  chatID,
				LocalEphemeralPublicKey: peerKey,
				Signature:               sig,
				KeyVersion:              version,
				HkdfSalt:                hkdfSalt,
				HkdfInfo:                hkdfInfo,
				Rekey:                   rekey,
			},
		},
	})
	if err := s.tryDeriveChatSecret(chatID); err != nil {
		s.log.Warn("derive chat secret after remote ready failed", zap.Error(err), zap.String("chat_id", chatID))
	}
}

func (s *AppRouterService) handleChatMessage(session *appSession, msg *approuterpb.ChatMessage) error {
	if msg == nil || msg.ChatId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}
	if len(msg.Payload) < minCiphertextBytes {
		return &routeError{code: "INVALID_FRAME", msg: "ciphertext envelope too small"}
	}

	var peer *chatParticipant
	var remote *remotePeer
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

	if tl.remote != nil {
		remote = tl.remote
	} else {
		peer = tl.peer(session.id)
	}

	if peer == nil && (remote == nil || !tl.readyRemote()) {
		s.mu.Unlock()
		return &routeError{code: "CHAT_NOT_READY", msg: "chat not ready"}
	}

	if sender.nextSeq > 0 {
		expected = sender.nextSeq + 1
	} else if msg.Sequence == 0 {
		expected = 0
	}

	if msg.Sequence != expected {
		if s.metrics != nil {
			s.metrics.recordRatchetFailure("sequence")
		}
		s.mu.Unlock()
		s.handleRatchetDivergence(msg.ChatId, ratchetDesync)
		return &routeError{code: "RATCHET_DESYNC", msg: fmt.Sprintf("expected sequence %d", expected)}
	}

	sender.nextSeq = msg.Sequence
	tl.markActive()

	dir := tl.ratchetDirection(sender.appID)
	if err := s.advanceRatchetLocked(tl, dir); err != nil {
		s.mu.Unlock()
		status := ratchetDesync
		code := "RATCHET_FAILED"
		if errors.Is(err, errKeyExpired) {
			status = ratchetExpired
			code = "REKEY_REQUIRED"
		}
		s.handleRatchetDivergence(msg.ChatId, status)
		return &routeError{code: code, msg: err.Error()}
	}

	if remote != nil {
		if remote.pendingAcks == nil {
			remote.pendingAcks = make(map[uint64]*appSession)
		}
		remote.pendingAcks[msg.Sequence] = session
		nodeID := remote.nodeID
		s.mu.Unlock()
		return s.forwardToRemote(nodeID, tl.id, msg)
	}

	peerSession := peer.session
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
	return s.pushFrame(peerSession, forward)
}

func (s *AppRouterService) forwardToRemote(nodeID, chatID string, msg *approuterpb.ChatMessage) error {
	if nodeID == "" {
		return &routeError{code: "ROUTE_UNAVAILABLE", msg: "remote node unknown"}
	}
	if s.routes == nil {
		return &routeError{code: "ROUTE_UNAVAILABLE", msg: "mesh routing not configured"}
	}

	frame := &nodemeshpb.RouteFrame{
		CorrelationId: chatID,
		Body: &nodemeshpb.RouteFrame_RelayMessage{
			RelayMessage: &nodemeshpb.RelayMessage{
				ChatId:   chatID,
				Payload:  append([]byte(nil), msg.Payload...),
				Sequence: msg.Sequence,
			},
		},
	}
	if err := s.routes.Send(context.Background(), nodeID, frame); err != nil {
		return &routeError{code: "ROUTE_UNAVAILABLE", msg: "failed to forward to remote"}
	}
	return nil
}

func (s *AppRouterService) sendRemoteTeardown(nodeID, chatID, reason string) {
	if nodeID == "" || s.routes == nil {
		return
	}
	frame := &nodemeshpb.RouteFrame{
		CorrelationId: chatID,
		Body: &nodemeshpb.RouteFrame_TeardownTieline{
			TeardownTieline: &nodemeshpb.TeardownTieline{
				ChatId: chatID,
				Reason: reason,
			},
		},
	}
	if err := s.routes.Send(context.Background(), nodeID, frame); err != nil {
		s.log.Warn("send remote teardown failed", zap.String("chat_id", chatID), zap.String("node_id", nodeID), zap.Error(err))
	}
}

func (s *AppRouterService) handleDeleteChat(session *appSession, del *approuterpb.DeleteChat) error {
	if del == nil || del.ChatId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}

	var sessions []*appSession
	var removed bool
	var remoteNode string

	s.mu.Lock()
	if tl, ok := s.chats[del.ChatId]; ok {
		tl.markActive()
		for _, p := range tl.participants {
			sessions = append(sessions, p.session)
		}
		if tl.remote != nil {
			remoteNode = tl.remote.nodeID
		}
		delete(s.chats, del.ChatId)
		tl.wipeSecrets()
		removed = true
	}
	s.mu.Unlock()

	if len(sessions) == 0 && remoteNode == "" {
		return &routeError{code: "CHAT_NOT_FOUND", msg: "chat not found"}
	}

	if removed {
		s.decChat()
		_ = s.registry.Delete(del.ChatId)
		s.eraseSecret(del.ChatId)
		s.recordErasure(firstNonEmpty(del.Reason, "deleted"))
	}

	if remoteNode != "" {
		s.sendRemoteTeardown(remoteNode, del.ChatId, "deleted_by_peer")
	}

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

// HandleRouteFrame implements mesh.RouteHandler for inbound RouteChat frames.
func (s *AppRouterService) HandleRouteFrame(ctx context.Context, fromNode string, frame *nodemeshpb.RouteFrame) (*nodemeshpb.RouteFrame, error) {
	switch body := frame.Body.(type) {
	case *nodemeshpb.RouteFrame_SetupTieline:
		return s.handleRouteSetup(fromNode, body.SetupTieline)
	case *nodemeshpb.RouteFrame_RelayMessage:
		return s.handleRouteRelay(body.RelayMessage)
	case *nodemeshpb.RouteFrame_RelayAck:
		return s.handleRouteAck(body.RelayAck)
	case *nodemeshpb.RouteFrame_TeardownTieline:
		return s.handleRouteTeardown(body.TeardownTieline)
	case *nodemeshpb.RouteFrame_Error:
		return nil, s.handleRouteError(frame.GetCorrelationId(), body.Error)
	default:
		return nil, &mesh.RouteError{Code: "UNSUPPORTED", Msg: "unsupported route frame"}
	}
}

// HandleRouteClosed tears down chats tied to a remote node on stream loss.
func (s *AppRouterService) HandleRouteClosed(nodeID string) {
	if nodeID == "" {
		return
	}
	s.handleNodeLoss(nodeID, "route_closed")
}

func (s *AppRouterService) handleRouteSetup(fromNode string, setup *nodemeshpb.SetupTieline) (*nodemeshpb.RouteFrame, error) {
	if setup == nil || setup.ChatId == "" {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "chat id required"}
	}
	if setup.TargetAppId == "" {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "target app id required"}
	}
	if setup.KeyVersion == 0 {
		setup.KeyVersion = 1
	}
	if setup.HkdfInfo == "" {
		setup.HkdfInfo = s.hkdfInfo
	}
	if len(setup.HkdfSalt) > maxHKDFSaltSize {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: fmt.Sprintf("hkdf salt too large (%d bytes)", len(setup.HkdfSalt))}
	}
	if len(setup.HkdfInfo) > maxHKDFInfoSize {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: fmt.Sprintf("hkdf info too large (%d bytes)", len(setup.HkdfInfo))}
	}
	if len(setup.SourceEphemeralKey) != pfs.KeySize || len(setup.SourcePublicKey) != ed25519.PublicKeySize {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "source keys invalid"}
	}
	if err := pfs.ValidatePublicKey(setup.SourceEphemeralKey); err != nil {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: err.Error()}
	}

	sourceID := appIdentityKey(ed25519.PublicKey(setup.SourcePublicKey))
	if setup.SourceAppId != "" && setup.SourceAppId != sourceID {
		return nil, &mesh.RouteError{Code: "AUTH_FAILED", Msg: "source app id mismatch"}
	}
	payload := handshakePayload(setup.ChatId, sourceID, setup.TargetAppId, setup.SourceEphemeralKey, setup.HkdfSalt, setup.HkdfInfo, setup.KeyVersion, setup.Rekey)
	if len(setup.Signature) == 0 || !ed25519.Verify(ed25519.PublicKey(setup.SourcePublicKey), payload, setup.Signature) {
		return nil, &mesh.RouteError{Code: "AUTH_FAILED", Msg: "setup signature invalid"}
	}

	if s.sessionByApp(setup.TargetAppId) == nil {
		return nil, &mesh.RouteError{Code: "TARGET_NOT_FOUND", Msg: "target app not connected"}
	}

	now := time.Now()
	s.mu.Lock()
	tl, ok := s.chats[setup.ChatId]
	if !ok {
		tl = newTieline(setup.ChatId)
		tl.metadata = cloneMetadata(setup.Metadata)
		s.chats[setup.ChatId] = tl
		_ = s.registry.Register(registry.ChatSession{
			ChatID:    setup.ChatId,
			CreatedAt: now,
			Metadata:  cloneMetadata(setup.Metadata),
		})
		s.incChat()
	}
	if err := tl.prepareVersion(setup.KeyVersion, setup.HkdfInfo, setup.HkdfSalt); err != nil {
		s.mu.Unlock()
		code := "KEY_MISMATCH"
		if errors.Is(err, errStaleKeyVersion) {
			code = "REPLAYED_KEY"
		}
		return nil, &mesh.RouteError{Code: code, Msg: err.Error()}
	}
	if tl.remote == nil {
		tl.remote = &remotePeer{
			nodeID:      fromNode,
			appID:       sourceID,
			pendingAcks: make(map[uint64]*appSession),
		}
	}
	if tl.remote.pendingAcks == nil {
		tl.remote.pendingAcks = make(map[uint64]*appSession)
	}
	tl.remote.nodeID = firstNonEmpty(tl.remote.nodeID, fromNode)
	tl.remote.appID = firstNonEmpty(tl.remote.appID, sourceID)
	tl.remote.ephemeralKey = cloneBytes(setup.SourceEphemeralKey)
	tl.remote.signature = cloneBytes(setup.Signature)
	tl.remote.keyVersion = setup.KeyVersion
	tl.remote.hkdfSalt = cloneBytes(setup.HkdfSalt)
	tl.remote.hkdfInfo = setup.HkdfInfo
	tl.remote.rekey = setup.Rekey
	tl.remote.startNotified = false
	tl.markActive()
	s.mu.Unlock()

	s.notifyRemoteReady(setup.ChatId)
	return nil, nil
}

func (s *AppRouterService) handleRouteRelay(relay *nodemeshpb.RelayMessage) (*nodemeshpb.RouteFrame, error) {
	if relay == nil || relay.ChatId == "" {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "chat id required"}
	}
	if len(relay.Payload) < minCiphertextBytes {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "ciphertext envelope too small"}
	}

	var target *appSession
	expected := uint64(1)

	s.mu.Lock()
	tl, ok := s.chats[relay.ChatId]
	if !ok || tl.remote == nil {
		s.mu.Unlock()
		return nil, &mesh.RouteError{Code: "CHAT_NOT_FOUND", Msg: "chat not found"}
	}
	if tl.remote.inboundSeq > 0 {
		expected = tl.remote.inboundSeq + 1
	} else if relay.Sequence == 0 {
		expected = 0
	}
	if relay.Sequence != expected {
		if s.metrics != nil {
			s.metrics.recordRatchetFailure("sequence")
		}
		s.mu.Unlock()
		s.handleRatchetDivergence(relay.ChatId, ratchetDesync)
		return nil, &mesh.RouteError{Code: "RATCHET_DESYNC", Msg: fmt.Sprintf("expected sequence %d", expected)}
	}

	for _, p := range tl.participants {
		target = p.session
		break
	}
	tl.remote.inboundSeq = relay.Sequence
	tl.markActive()

	dir := tl.ratchetDirection(tl.remote.appID)
	if err := s.advanceRatchetLocked(tl, dir); err != nil {
		s.mu.Unlock()
		status := ratchetDesync
		code := "RATCHET_FAILED"
		if errors.Is(err, errKeyExpired) {
			status = ratchetExpired
			code = "REKEY_REQUIRED"
		}
		s.handleRatchetDivergence(relay.ChatId, status)
		return nil, &mesh.RouteError{Code: code, Msg: err.Error()}
	}
	s.mu.Unlock()

	if target == nil {
		return nil, &mesh.RouteError{Code: "CHAT_NOT_READY", Msg: "chat not ready"}
	}

	if err := s.pushFrame(target, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessage{
			ChatMessage: &approuterpb.ChatMessage{
				ChatId:   relay.ChatId,
				Payload:  append([]byte(nil), relay.Payload...),
				Sequence: relay.Sequence,
			},
		},
	}); err != nil {
		return nil, err
	}

	return &nodemeshpb.RouteFrame{
		CorrelationId: relay.ChatId,
		Body: &nodemeshpb.RouteFrame_RelayAck{
			RelayAck: &nodemeshpb.RelayAck{
				ChatId:   relay.ChatId,
				Sequence: relay.Sequence,
			},
		},
	}, nil
}

func (s *AppRouterService) handleRouteAck(ack *nodemeshpb.RelayAck) (*nodemeshpb.RouteFrame, error) {
	if ack == nil || ack.ChatId == "" {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "chat id required"}
	}

	var sender *appSession

	s.mu.Lock()
	if tl, ok := s.chats[ack.ChatId]; ok && tl.remote != nil {
		if tl.remote.pendingAcks != nil {
			sender = tl.remote.pendingAcks[ack.Sequence]
			delete(tl.remote.pendingAcks, ack.Sequence)
		}
		tl.markActive()
	}
	s.mu.Unlock()

	if sender == nil {
		return nil, nil
	}

	_ = s.pushFrame(sender, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_ChatMessageAck{
			ChatMessageAck: &approuterpb.ChatMessageAck{
				ChatId:   ack.ChatId,
				Sequence: ack.Sequence,
			},
		},
	})
	return nil, nil
}

func (s *AppRouterService) handleRouteTeardown(teardown *nodemeshpb.TeardownTieline) (*nodemeshpb.RouteFrame, error) {
	if teardown == nil || teardown.ChatId == "" {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "chat id required"}
	}

	var sessions []*appSession
	var removed bool

	s.mu.Lock()
	if tl, ok := s.chats[teardown.ChatId]; ok {
		for _, p := range tl.participants {
			sessions = append(sessions, p.session)
		}
		delete(s.chats, teardown.ChatId)
		tl.wipeSecrets()
		removed = true
	}
	s.mu.Unlock()

	if removed {
		s.decChat()
		_ = s.registry.Delete(teardown.ChatId)
		s.eraseSecret(teardown.ChatId)
		s.recordErasure(firstNonEmpty(teardown.Reason, "deleted_by_peer"))
	}

	for _, sess := range sessions {
		status := "deleted_by_peer"
		switch teardown.Reason {
		case "expired", "route_closed", "route_unavailable":
			status = teardown.Reason
		case "session_closed":
			status = "route_closed"
		}
		_ = s.pushFrame(sess, &approuterpb.AppFrame{
			Body: &approuterpb.AppFrame_DeleteChatAck{
				DeleteChatAck: &approuterpb.DeleteChatAck{
					ChatId: teardown.ChatId,
					Status: status,
				},
			},
		})
	}

	return nil, nil
}

func (s *AppRouterService) handleRouteError(chatID string, rerr *nodemeshpb.RouteError) error {
	if chatID == "" || rerr == nil {
		return nil
	}
	var sessions []*appSession
	var removed bool

	s.mu.Lock()
	if tl, ok := s.chats[chatID]; ok {
		for _, p := range tl.participants {
			sessions = append(sessions, p.session)
		}
		delete(s.chats, chatID)
		tl.wipeSecrets()
		removed = true
	}
	s.mu.Unlock()

	if removed {
		s.decChat()
		_ = s.registry.Delete(chatID)
		s.eraseSecret(chatID)
		s.recordErasure(firstNonEmpty(rerr.GetCode(), "route_error"))
	}

	for _, sess := range sessions {
		_ = s.pushFrame(sess, &approuterpb.AppFrame{
			Body: &approuterpb.AppFrame_Error{
				Error: &approuterpb.Error{Code: rerr.GetCode(), Message: rerr.GetMessage()},
			},
		})
	}
	return nil
}

func (s *AppRouterService) handleNodeLoss(nodeID, reason string) {
	type removed struct {
		id       string
		sessions []*appSession
	}
	var chats []removed

	s.mu.Lock()
	for chatID, tl := range s.chats {
		if tl.remote != nil && tl.remote.nodeID == nodeID {
			participants := make([]*appSession, 0, len(tl.participants))
			for _, p := range tl.participants {
				participants = append(participants, p.session)
			}
			tl.wipeSecrets()
			delete(s.chats, chatID)
			chats = append(chats, removed{id: chatID, sessions: participants})
		}
	}
	s.mu.Unlock()

	for _, chat := range chats {
		s.decChat()
		_ = s.registry.Delete(chat.id)
		s.eraseSecret(chat.id)
		s.recordErasure(reason)
		for _, sess := range chat.sessions {
			_ = s.pushFrame(sess, &approuterpb.AppFrame{
				Body: &approuterpb.AppFrame_DeleteChatAck{
					DeleteChatAck: &approuterpb.DeleteChatAck{
						ChatId: chat.id,
						Status: reason,
					},
				},
			})
		}
	}
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

func (s *AppRouterService) handleFindApp(session *appSession, find *approuterpb.FindApp) error {
	if find == nil || find.TargetAppId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "target app id required"}
	}

	nodeID, local, err := s.resolveRoute(find.TargetAppId, find.TargetNodeHint)
	status := "unknown"
	if err == nil && nodeID != "" {
		if local {
			status = "local"
		} else {
			status = "found"
		}
	}

	return s.pushFrame(session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_FindAppResult{
			FindAppResult: &approuterpb.FindAppResult{
				TargetAppId: find.TargetAppId,
				NodeId:      nodeID,
				Status:      status,
			},
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

	type removed struct {
		id         string
		remoteNode string
	}
	var deletedChats []removed

	s.mu.Lock()
	delete(s.sessions, session.id)
	delete(s.byAppID, session.appID)
	for chatID, tl := range s.chats {
		if _, ok := tl.participants[session.id]; ok {
			tl.removeParticipant(session.id)
			if tl.isEmpty() {
				tl.wipeSecrets()
				delete(s.chats, chatID)
				remoteNode := ""
				if tl.remote != nil {
					remoteNode = tl.remote.nodeID
				}
				deletedChats = append(deletedChats, removed{id: chatID, remoteNode: remoteNode})
			}
		}
	}
	close(session.sendCh)
	s.mu.Unlock()

	if s.apps != nil && session.appID != "" {
		s.apps.Remove(session.appID)
	}
	s.syncLocalApps(time.Now())

	s.decSession()
	for _, chat := range deletedChats {
		_ = s.registry.Delete(chat.id)
		s.eraseSecret(chat.id)
		s.recordErasure("session_closed")
		s.decChat()
		if chat.remoteNode != "" {
			s.sendRemoteTeardown(chat.remoteNode, chat.id, "session_closed")
		}
	}

	s.log.Info("app disconnected", zap.String("session_id", session.id))
}

func (s *AppRouterService) tryDeriveChatSecret(chatID string) error {
	material, ready, err := s.derivationMaterial(chatID)
	if err != nil {
		s.teardownOnFailure(chatID, err)
		return err
	}
	if !ready {
		return nil
	}
	if err := s.persistDerivedSecret(material); err != nil {
		s.teardownOnFailure(chatID, err)
		return err
	}

	s.mu.Lock()
	if tl, ok := s.chats[chatID]; ok {
		tl.derivedVersion = material.keyVersion
	}
	s.mu.Unlock()
	return nil
}

func (s *AppRouterService) derivationMaterial(chatID string) (derivationMaterial, bool, error) {
	s.mu.Lock()
	tl, ok := s.chats[chatID]
	if !ok {
		s.mu.Unlock()
		return derivationMaterial{}, false, nil
	}
	mat, ready, err := tl.derivationMaterial()
	s.mu.Unlock()
	return mat, ready, err
}

func (s *AppRouterService) persistDerivedSecret(material derivationMaterial) error {
	if s.keystore == nil {
		return nil
	}
	if len(material.local.private) != pfs.KeySize || len(material.local.public) != pfs.KeySize || len(material.remotePublic) != pfs.KeySize {
		return fmt.Errorf("incomplete key material for derivation")
	}
	if material.localAppID == "" || material.remoteAppID == "" {
		return fmt.Errorf("missing app identifiers for ratchet state")
	}

	shared, err := pfs.SharedSecret(material.local.private, material.remotePublic)
	if err != nil {
		return fmt.Errorf("derive shared secret: %w", err)
	}
	defer zeroBytes(shared)

	keys, err := pfs.DeriveSessionKeys(shared, material.hkdfSalt, []byte(material.hkdfInfo), s.hkdfHash, pfs.SessionKeySizes{})
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}
	defer keys.Zero()

	localID, err := pfs.KeyIdentifier(material.local.public)
	if err != nil {
		return fmt.Errorf("local key id: %w", err)
	}
	remoteID, err := pfs.KeyIdentifier(material.remotePublic)
	if err != nil {
		return fmt.Errorf("remote key id: %w", err)
	}

	now := time.Now().UTC()
	record := keystore.ChatSecretRecord{
		ChatID:       material.chatID,
		KeyVersion:   material.keyVersion,
		LocalKeyID:   localID,
		RemoteKeyID:  remoteID,
		LocalPublic:  cloneBytes(material.local.public),
		RemotePublic: cloneBytes(material.remotePublic),
		LocalPrivate: cloneBytes(material.local.private),
		LocalAppID:   material.localAppID,
		RemoteAppID:  material.remoteAppID,
		HKDFSalt:     cloneBytes(material.hkdfSalt),
		HKDFInfo:     []byte(material.hkdfInfo),
		SendKey:      cloneBytes(keys.SendKey),
		RecvKey:      cloneBytes(keys.RecvKey),
		MACKey:       cloneBytes(keys.MACKey),
		RatchetSeed:  cloneBytes(keys.RatchetKey),
		SendCount:    0,
		RecvCount:    0,
		CreatedAt:    now,
	}
	if material.keyVersion > 1 {
		record.RotatedAt = now
	}
	defer record.Zero()

	snapshot := record.Clone()
	if err := s.keystore.StoreChatSecret(context.Background(), record); err != nil {
		return fmt.Errorf("persist chat secret: %w", err)
	}
	s.cacheRatchetState(material.chatID, snapshot)
	return nil
}

func (s *AppRouterService) cacheRatchetState(chatID string, record keystore.ChatSecretRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tl, ok := s.chats[chatID]
	if !ok {
		return
	}
	if tl.secret != nil {
		tl.secret.Zero()
	}
	clone := record.Clone()
	tl.secret = &clone
	tl.ratchetLocalID = record.LocalAppID
	tl.ratchetRemoteID = record.RemoteAppID
	tl.lastRatchet = record.CreatedAt
}

func (s *AppRouterService) eraseSecret(chatID string) {
	if s.keystore == nil {
		return
	}
	if err := s.keystore.DeleteChatSecret(context.Background(), chatID); err != nil {
		s.log.Warn("erase chat secret", zap.Error(err), zap.String("chat_id", chatID))
	}
}

func (s *AppRouterService) teardownOnFailure(chatID string, deriveErr error) {
	var sessions []*appSession
	var remoteNode string
	var removed bool

	s.mu.Lock()
	if tl, ok := s.chats[chatID]; ok {
		for _, p := range tl.participants {
			sessions = append(sessions, p.session)
		}
		if tl.remote != nil {
			remoteNode = tl.remote.nodeID
		}
		tl.wipeSecrets()
		delete(s.chats, chatID)
		removed = true
	}
	s.mu.Unlock()

	if removed {
		s.decChat()
		_ = s.registry.Delete(chatID)
		s.eraseSecret(chatID)
		s.recordErasure("derivation_failed")
	}

	if remoteNode != "" {
		s.sendRemoteTeardown(remoteNode, chatID, "derivation_failed")
	}
	for _, sess := range sessions {
		_ = s.pushFrame(sess, &approuterpb.AppFrame{
			Body: &approuterpb.AppFrame_Error{
				Error: &approuterpb.Error{Code: "DERIVATION_FAILED", Message: deriveErr.Error()},
			},
		})
	}
}

func (s *AppRouterService) advanceRatchetLocked(tl *tieline, dir ratchetDirection) error {
	if dir == "" {
		if s.metrics != nil {
			s.metrics.recordRatchetFailure("missing_direction")
		}
		return errRatchetMissing
	}
	if tl == nil || tl.secret == nil {
		if s.metrics != nil {
			s.metrics.recordRatchetFailure("missing_state")
		}
		return errRatchetMissing
	}
	if s.maxKeyLifetime > 0 && tl.keyExpired(time.Now(), s.maxKeyLifetime) {
		if s.metrics != nil {
			s.metrics.recordRatchetFailure("expired")
		}
		return errKeyExpired
	}
	if err := tl.advanceRatchet(dir, s.hkdfHash); err != nil {
		if s.metrics != nil {
			s.metrics.recordRatchetFailure("advance")
		}
		return err
	}
	if s.metrics != nil {
		s.metrics.recordRatchetAdvance(string(dir))
	}
	if s.keystore != nil && tl.secret != nil {
		record := tl.secret.Clone()
		defer record.Zero()
		if err := s.keystore.StoreChatSecret(context.Background(), record); err != nil {
			if s.metrics != nil {
				s.metrics.recordRatchetFailure("persist")
			}
			return fmt.Errorf("persist ratchet state: %w", err)
		}
	}
	return nil
}

func (s *AppRouterService) handleRatchetDivergence(chatID, status string) {
	if status == "" {
		status = ratchetDesync
	}
	if s.metrics != nil {
		s.metrics.recordRatchetFailure(status)
	}
	var sessions []*appSession
	var remoteNode string
	var removed bool

	s.mu.Lock()
	if tl, ok := s.chats[chatID]; ok {
		for _, p := range tl.participants {
			sessions = append(sessions, p.session)
		}
		if tl.remote != nil {
			remoteNode = tl.remote.nodeID
		}
		tl.wipeSecrets()
		delete(s.chats, chatID)
		removed = true
	}
	s.mu.Unlock()

	if removed {
		s.decChat()
		_ = s.registry.Delete(chatID)
		s.eraseSecret(chatID)
		s.recordErasure(status)
	}

	if remoteNode != "" {
		s.sendRemoteTeardown(remoteNode, chatID, status)
	}

	for _, sess := range sessions {
		_ = s.pushFrame(sess, &approuterpb.AppFrame{
			Body: &approuterpb.AppFrame_DeleteChatAck{
				DeleteChatAck: &approuterpb.DeleteChatAck{
					ChatId: chatID,
					Status: status,
				},
			},
		})
	}
}

func (s *AppRouterService) expireIdleChats(now time.Time) {
	if s.chatIdleTimeout <= 0 {
		return
	}

	type expiring struct {
		id         string
		sessions   []*appSession
		remoteNode string
	}

	var expired []expiring

	s.mu.Lock()
	for chatID, tl := range s.chats {
		if now.Sub(tl.lastActivity) > s.chatIdleTimeout {
			tl.wipeSecrets()
			sessions := make([]*appSession, 0, len(tl.participants))
			for _, p := range tl.participants {
				sessions = append(sessions, p.session)
			}
			delete(s.chats, chatID)
			nodeID := ""
			if tl.remote != nil {
				nodeID = tl.remote.nodeID
			}
			expired = append(expired, expiring{id: chatID, sessions: sessions, remoteNode: nodeID})
		}
	}
	s.mu.Unlock()

	for _, chat := range expired {
		s.decChat()
		_ = s.registry.Delete(chat.id)
		s.eraseSecret(chat.id)
		s.recordChatExpiry()
		s.recordErasure("expired")
		if chat.remoteNode != "" {
			s.sendRemoteTeardown(chat.remoteNode, chat.id, "expired")
		}
		for _, sess := range chat.sessions {
			_ = s.pushFrame(sess, &approuterpb.AppFrame{
				Body: &approuterpb.AppFrame_DeleteChatAck{
					DeleteChatAck: &approuterpb.DeleteChatAck{
						ChatId: chat.id,
						Status: "expired",
					},
				},
			})
		}
		s.log.Info("expired idle chat", zap.String("chat_id", chat.id))
	}
}

func (s *AppRouterService) observe(op string, start time.Time, err error) {
	if s.metrics == nil {
		return
	}
	s.metrics.observeLatency(op, time.Since(start))
	if err != nil {
		code := "internal"
		var rerr *routeError
		if errors.As(err, &rerr) && rerr.code != "" {
			code = rerr.code
		}
		s.metrics.recordError(code)
	}
}

func (s *AppRouterService) touchSession(session *appSession) {
	s.mu.Lock()
	session.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *AppRouterService) incSession() {
	if s.metrics == nil {
		return
	}
	s.metrics.incSession()
}

func (s *AppRouterService) decSession() {
	if s.metrics == nil {
		return
	}
	s.metrics.decSession()
}

func (s *AppRouterService) incChat() {
	if s.metrics == nil {
		return
	}
	s.metrics.incChat()
}

func (s *AppRouterService) decChat() {
	if s.metrics == nil {
		return
	}
	s.metrics.decChat()
}

func (s *AppRouterService) recordChatExpiry() {
	if s.metrics == nil {
		return
	}
	s.metrics.recordChatExpiry()
}

func (s *AppRouterService) recordErasure(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.recordErasure(reason)
}

func (s *AppRouterService) snapshotRatchets() []ratchetStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ratchetStatus, 0, len(s.chats))
	for chatID, tl := range s.chats {
		if tl.secret == nil {
			continue
		}
		status := ratchetStatus{
			ChatID:      chatID,
			KeyVersion:  tl.secret.KeyVersion,
			SendCount:   tl.secret.SendCount,
			RecvCount:   tl.secret.RecvCount,
			LastRatchet: tl.lastRatchet,
			LocalAppID:  tl.ratchetLocalID,
			RemoteAppID: tl.ratchetRemoteID,
			Derived:     tl.derivedVersion > 0,
		}
		if tl.remote != nil {
			status.RemoteNodeID = tl.remote.nodeID
		}
		out = append(out, status)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ChatID < out[j].ChatID
	})
	return out
}

func (s *AppRouterService) sessionByApp(appID string) *appSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byAppID[appID]
}

func (s *AppRouterService) resolveRoute(targetAppID, hint string) (nodeID string, local bool, err error) {
	if targetAppID == "" {
		return "", false, errors.New("target app id required")
	}
	if sess := s.sessionByApp(targetAppID); sess != nil {
		return s.nodeID, true, nil
	}
	if s.store != nil {
		if app, ok := s.store.ResolveApp(targetAppID); ok {
			return app.NodeID, app.NodeID == s.nodeID, nil
		}
	}
	if hint != "" {
		return hint, hint == s.nodeID, nil
	}
	// Fallback: assume local and wait for the peer to connect if discovery has not recorded the target yet.
	return s.nodeID, true, nil
}

func (s *AppRouterService) syncLocalApps(now time.Time) {
	if s.store == nil || s.apps == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	s.store.SetLocalApps(s.apps.List(), now)
}

func metricOp(frame *approuterpb.AppFrame) string {
	if frame == nil {
		return "unknown"
	}
	switch frame.Body.(type) {
	case *approuterpb.AppFrame_StartChat:
		return "start_chat"
	case *approuterpb.AppFrame_ChatMessage:
		return "chat_message"
	case *approuterpb.AppFrame_DeleteChat:
		return "delete_chat"
	case *approuterpb.AppFrame_Heartbeat:
		return "heartbeat"
	case *approuterpb.AppFrame_FindApp:
		return "find_app"
	default:
		return "unknown"
	}
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	return append([]byte(nil), in...)
}

func cloneMetadata(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func handshakePayload(chatID, sourceAppID, targetAppID string, public, hkdfSalt []byte, hkdfInfo string, version uint32, rekey bool) []byte {
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

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func appIdentityKey(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
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

func hashFromName(name string) crypto.Hash {
	switch name {
	case "sha256", "":
		return crypto.SHA256
	case "sha512":
		return crypto.SHA512
	default:
		return 0
	}
}

func generateSessionID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func ratchetStep(seed, current []byte, hash crypto.Hash, label byte) ([]byte, error) {
	if len(current) != pfs.KeySize {
		return nil, fmt.Errorf("ratchet key must be %d bytes (got %d)", pfs.KeySize, len(current))
	}
	if len(seed) == 0 {
		return nil, errRatchetMissing
	}
	h := hash.New()
	h.Write(seed)
	h.Write([]byte{label})
	h.Write(current)
	out := h.Sum(nil)
	if len(out) < pfs.KeySize {
		return nil, fmt.Errorf("ratchet hash output too short")
	}
	return append([]byte(nil), out[:pfs.KeySize]...), nil
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
	lastSeen     time.Time
	appID        string
}

// chatParticipant wraps per-chat sender state.
type chatParticipant struct {
	session *appSession
	keys    keyMaterial
	nextSeq uint64
	appID   string
}

type keyMaterial struct {
	public     []byte
	private    []byte
	signature  []byte
	keyVersion uint32
	hkdfSalt   []byte
	hkdfInfo   string
	rekey      bool
}

type peerNotification struct {
	target     *appSession
	chatID     string
	peerPublic []byte
	signature  []byte
	keyVersion uint32
	hkdfSalt   []byte
	hkdfInfo   string
	rekey      bool
}

type ratchetStatus struct {
	ChatID       string    `json:"chat_id"`
	KeyVersion   uint32    `json:"key_version"`
	SendCount    uint64    `json:"send_count"`
	RecvCount    uint64    `json:"recv_count"`
	LastRatchet  time.Time `json:"last_ratchet_at,omitempty"`
	LocalAppID   string    `json:"local_app_id,omitempty"`
	RemoteAppID  string    `json:"remote_app_id,omitempty"`
	Derived      bool      `json:"derived"`
	RemoteNodeID string    `json:"remote_node_id,omitempty"`
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
	id              string
	participants    map[string]*chatParticipant
	remote          *remotePeer
	lastActivity    time.Time
	metadata        map[string]string
	keyVersion      uint32
	hkdfInfo        string
	hkdfSalt        []byte
	derivedVersion  uint32
	secret          *keystore.ChatSecretRecord
	ratchetLocalID  string
	ratchetRemoteID string
	lastRatchet     time.Time
}

type remotePeer struct {
	nodeID        string
	appID         string
	ephemeralKey  []byte
	signature     []byte
	keyVersion    uint32
	hkdfSalt      []byte
	hkdfInfo      string
	rekey         bool
	inboundSeq    uint64
	pendingAcks   map[uint64]*appSession
	startNotified bool
}

func newTieline(id string) *tieline {
	return &tieline{
		id:           id,
		participants: make(map[string]*chatParticipant),
		lastActivity: time.Now(),
	}
}

func (t *tieline) prepareVersion(version uint32, info string, salt []byte) error {
	if version == 0 {
		version = 1
	}
	if info == "" {
		return errors.New("hkdf info required")
	}
	if t.keyVersion == 0 {
		t.keyVersion = version
		t.hkdfInfo = info
		t.hkdfSalt = cloneBytes(salt)
		t.derivedVersion = 0
		return nil
	}
	if version < t.keyVersion {
		return fmt.Errorf("%w %d (current %d)", errStaleKeyVersion, version, t.keyVersion)
	}
	if version > t.keyVersion {
		t.wipeSecrets()
		t.participants = make(map[string]*chatParticipant)
		t.remote = nil
		t.keyVersion = version
		t.hkdfInfo = info
		t.hkdfSalt = cloneBytes(salt)
		t.derivedVersion = 0
		return nil
	}

	if t.hkdfInfo != "" && t.hkdfInfo != info {
		return fmt.Errorf("%w", errHKDFMismatch)
	}
	if len(t.hkdfSalt) > 0 && len(salt) > 0 && !bytes.Equal(t.hkdfSalt, salt) {
		return fmt.Errorf("%w", errHKDFMismatch)
	}
	if t.hkdfInfo == "" {
		t.hkdfInfo = info
	}
	if len(t.hkdfSalt) == 0 && len(salt) > 0 {
		t.hkdfSalt = cloneBytes(salt)
	}
	return nil
}

func (t *tieline) addOrUpdateParticipant(p *chatParticipant) error {
	if p.keys.keyVersion != t.keyVersion {
		return fmt.Errorf("key version mismatch (got %d, expected %d)", p.keys.keyVersion, t.keyVersion)
	}
	if t.hkdfInfo != "" && p.keys.hkdfInfo != "" && t.hkdfInfo != p.keys.hkdfInfo {
		return fmt.Errorf("%w", errHKDFMismatch)
	}
	if len(t.hkdfSalt) > 0 && len(p.keys.hkdfSalt) > 0 && !bytes.Equal(t.hkdfSalt, p.keys.hkdfSalt) {
		return fmt.Errorf("%w", errHKDFMismatch)
	}
	if existing, ok := t.participants[p.session.id]; ok {
		if p.keys.keyVersion == existing.keys.keyVersion {
			return fmt.Errorf("%w", errStaleKeyVersion)
		}
		if p.keys.keyVersion < existing.keys.keyVersion {
			return errors.New("stale key version for participant")
		}
		t.participants[p.session.id] = p
		return nil
	}
	if len(t.participants) >= 2 {
		return errors.New("chat already has two participants")
	}
	for sid, existing := range t.participants {
		if existing.appID != "" && existing.appID == p.appID {
			if p.keys.keyVersion > existing.keys.keyVersion {
				delete(t.participants, sid)
				break
			}
			return errors.New("app already registered in chat")
		}
	}
	t.participants[p.session.id] = p
	return nil
}

func (t *tieline) removeParticipant(sessionID string) {
	if p, ok := t.participants[sessionID]; ok {
		zeroBytes(p.keys.public)
		zeroBytes(p.keys.private)
		zeroBytes(p.keys.signature)
		zeroBytes(p.keys.hkdfSalt)
		delete(t.participants, sessionID)
	}
}

func (t *tieline) peer(sessionID string) *chatParticipant {
	for sid, p := range t.participants {
		if sid != sessionID {
			return p
		}
	}
	return nil
}

func (t *tieline) readyLocal() bool {
	if t.keyVersion == 0 || len(t.participants) != 2 {
		return false
	}
	for _, p := range t.participants {
		if p.keys.keyVersion != t.keyVersion {
			return false
		}
	}
	return true
}

func (t *tieline) readyRemote() bool {
	if t.keyVersion == 0 || len(t.participants) != 1 || t.remote == nil {
		return false
	}
	if t.remote.keyVersion != 0 && t.remote.keyVersion != t.keyVersion {
		return false
	}
	if len(t.remote.ephemeralKey) != pfs.KeySize {
		return false
	}
	if t.remote.hkdfInfo != "" && t.hkdfInfo != "" && t.remote.hkdfInfo != t.hkdfInfo {
		return false
	}
	if len(t.remote.hkdfSalt) > 0 && len(t.hkdfSalt) > 0 && !bytes.Equal(t.remote.hkdfSalt, t.hkdfSalt) {
		return false
	}
	return true
}

func (t *tieline) ready() bool {
	return t.readyLocal() || t.readyRemote()
}

func (t *tieline) isEmpty() bool {
	return len(t.participants) == 0
}

func (t *tieline) markActive() {
	t.lastActivity = time.Now()
}

func (t *tieline) wipeSecrets() {
	for _, p := range t.participants {
		zeroBytes(p.keys.public)
		zeroBytes(p.keys.private)
		zeroBytes(p.keys.signature)
		zeroBytes(p.keys.hkdfSalt)
	}
	if t.remote != nil {
		zeroBytes(t.remote.ephemeralKey)
		zeroBytes(t.remote.signature)
		zeroBytes(t.remote.hkdfSalt)
	}
	if t.secret != nil {
		t.secret.Zero()
		t.secret = nil
	}
	zeroBytes(t.hkdfSalt)
	t.ratchetLocalID = ""
	t.ratchetRemoteID = ""
	t.lastRatchet = time.Time{}
}

func (t *tieline) participantForApp(appID string) *chatParticipant {
	for _, p := range t.participants {
		if p.appID == appID {
			return p
		}
	}
	return nil
}

func (t *tieline) ratchetDirection(appID string) ratchetDirection {
	if appID == "" {
		return ""
	}
	if appID == t.ratchetLocalID {
		return ratchetSend
	}
	if appID == t.ratchetRemoteID {
		return ratchetRecv
	}
	return ""
}

func (t *tieline) keyExpired(now time.Time, max time.Duration) bool {
	if t.secret == nil || max <= 0 {
		return false
	}
	start := t.secret.RotatedAt
	if start.IsZero() {
		start = t.secret.CreatedAt
	}
	if start.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.Sub(start) > max
}

type derivationMaterial struct {
	chatID       string
	keyVersion   uint32
	hkdfSalt     []byte
	hkdfInfo     string
	localAppID   string
	remoteAppID  string
	local        keyMaterial
	remotePublic []byte
}

func (t *tieline) derivationMaterial() (derivationMaterial, bool, error) {
	if t.keyVersion == 0 || t.derivedVersion == t.keyVersion {
		return derivationMaterial{}, false, nil
	}

	if t.readyLocal() {
		var a, b *chatParticipant
		for _, p := range t.participants {
			if a == nil {
				a = p
			} else {
				b = p
				break
			}
		}
		if a == nil || b == nil {
			return derivationMaterial{}, false, nil
		}
		local := a
		remote := b
		if b.appID < a.appID {
			local, remote = b, a
		}
		if len(local.keys.private) != pfs.KeySize {
			return derivationMaterial{}, false, fmt.Errorf("local private key missing for %s", local.appID)
		}
		return derivationMaterial{
			chatID:       t.id,
			keyVersion:   t.keyVersion,
			hkdfSalt:     cloneBytes(t.hkdfSalt),
			hkdfInfo:     t.hkdfInfo,
			localAppID:   local.appID,
			remoteAppID:  remote.appID,
			local:        local.keys,
			remotePublic: cloneBytes(remote.keys.public),
		}, true, nil
	}

	if t.readyRemote() && t.remote != nil {
		var local *chatParticipant
		for _, p := range t.participants {
			local = p
			break
		}
		if local == nil {
			return derivationMaterial{}, false, nil
		}
		if len(local.keys.private) != pfs.KeySize {
			return derivationMaterial{}, false, fmt.Errorf("local private key missing for %s", local.appID)
		}
		return derivationMaterial{
			chatID:       t.id,
			keyVersion:   t.keyVersion,
			hkdfSalt:     cloneBytes(t.hkdfSalt),
			hkdfInfo:     t.hkdfInfo,
			localAppID:   local.appID,
			remoteAppID:  t.remote.appID,
			local:        local.keys,
			remotePublic: cloneBytes(t.remote.ephemeralKey),
		}, true, nil
	}

	return derivationMaterial{}, false, nil
}

func (t *tieline) advanceRatchet(dir ratchetDirection, hash crypto.Hash) error {
	if t.secret == nil {
		return errRatchetMissing
	}
	if !hash.Available() {
		return fmt.Errorf("hash %v unavailable for ratchet", hash)
	}
	if len(t.secret.RatchetSeed) == 0 {
		return errRatchetMissing
	}

	now := time.Now()
	switch dir {
	case ratchetSend:
		next, err := ratchetStep(t.secret.RatchetSeed, t.secret.SendKey, hash, 's')
		if err != nil {
			return err
		}
		zeroBytes(t.secret.SendKey)
		t.secret.SendKey = next
		t.secret.SendCount++
	case ratchetRecv:
		next, err := ratchetStep(t.secret.RatchetSeed, t.secret.RecvKey, hash, 'r')
		if err != nil {
			return err
		}
		zeroBytes(t.secret.RecvKey)
		t.secret.RecvKey = next
		t.secret.RecvCount++
	default:
		return fmt.Errorf("unknown ratchet direction %q", dir)
	}
	t.lastRatchet = now
	return nil
}
