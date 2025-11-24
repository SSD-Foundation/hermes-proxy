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

	nodeID string
	apps   registry.AppRegistry
	store  *mesh.Store
	routes *mesh.RouteClientPool

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
	if start == nil || start.ChatId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "chat id required"}
	}
	if start.TargetAppId == "" {
		return &routeError{code: "INVALID_FRAME", msg: "target app id required"}
	}
	if len(start.PeerPublicEphemeralKey) == 0 {
		return &routeError{code: "INVALID_FRAME", msg: "ephemeral key required"}
	}
	if len(start.Signature) == 0 || !ed25519.Verify(session.appPublicKey, start.PeerPublicEphemeralKey, start.Signature) {
		return &routeError{code: "AUTH_FAILED", msg: "start chat signature invalid"}
	}

	routeNode, localRoute, err := s.resolveRoute(start.TargetAppId, start.TargetNodeHint)
	if err != nil {
		return &routeError{code: "TARGET_NOT_FOUND", msg: err.Error()}
	}

	participant := &chatParticipant{
		session:      session,
		ephemeralKey: append([]byte(nil), start.PeerPublicEphemeralKey...),
		appID:        session.appID,
	}

	var notifications []peerNotification
	var combinedKeys [][]byte
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

	if err := tl.addParticipant(participant); err != nil {
		s.mu.Unlock()
		return &routeError{code: "INVALID_FRAME", msg: err.Error()}
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
					target:  p.session,
					chatID:  tl.id,
					peerKey: append([]byte(nil), peer.ephemeralKey...),
				})
			}
			combinedKeys = tl.combinedKeys()
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
						ChatId:                 n.chatID,
						PeerPublicEphemeralKey: n.peerKey,
					},
				},
			})
		}
		s.persistChatSecret(start.ChatId, combinedKeys)
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
				SourceEphemeralKey: start.PeerPublicEphemeralKey,
				Signature:          start.Signature,
				Metadata:           cloneMetadata(start.Metadata),
				SourceNodeId:       s.nodeID,
				SourcePublicKey:    append([]byte(nil), session.appPublicKey...),
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
	peerKey := append([]byte(nil), tl.remote.ephemeralKey...)
	tl.remote.startNotified = true
	combined := tl.combinedKeys()
	s.mu.Unlock()

	_ = s.pushFrame(local.session, &approuterpb.AppFrame{
		Body: &approuterpb.AppFrame_StartChat{
			StartChat: &approuterpb.StartChat{
				ChatId:                 chatID,
				PeerPublicEphemeralKey: peerKey,
			},
		},
	})
	s.persistChatSecret(chatID, combined)
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
		s.mu.Unlock()
		return &routeError{code: "BAD_SEQUENCE", msg: fmt.Sprintf("expected sequence %d", expected)}
	}

	sender.nextSeq = msg.Sequence
	tl.markActive()

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
	if len(setup.SourceEphemeralKey) == 0 || len(setup.Signature) == 0 {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "ephemeral key and signature required"}
	}
	if len(setup.SourcePublicKey) != ed25519.PublicKeySize {
		return nil, &mesh.RouteError{Code: "INVALID_FRAME", Msg: "source public key invalid"}
	}

	sourceID := appIdentityKey(ed25519.PublicKey(setup.SourcePublicKey))
	if setup.SourceAppId != "" && setup.SourceAppId != sourceID {
		return nil, &mesh.RouteError{Code: "AUTH_FAILED", Msg: "source app id mismatch"}
	}
	if !ed25519.Verify(ed25519.PublicKey(setup.SourcePublicKey), setup.SourceEphemeralKey, setup.Signature) {
		return nil, &mesh.RouteError{Code: "AUTH_FAILED", Msg: "setup signature invalid"}
	}

	target := s.sessionByApp(setup.TargetAppId)
	if target == nil {
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
	if tl.remote == nil {
		tl.remote = &remotePeer{
			nodeID:      fromNode,
			appID:       sourceID,
			pendingAcks: make(map[uint64]*appSession),
		}
	} else {
		if tl.remote.pendingAcks == nil {
			tl.remote.pendingAcks = make(map[uint64]*appSession)
		}
		if tl.remote.nodeID == "" {
			tl.remote.nodeID = fromNode
		}
	}
	tl.remote.ephemeralKey = append([]byte(nil), setup.SourceEphemeralKey...)
	if tl.remote.appID == "" {
		tl.remote.appID = sourceID
	}
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
		s.mu.Unlock()
		return nil, &mesh.RouteError{Code: "BAD_SEQUENCE", Msg: fmt.Sprintf("expected sequence %d", expected)}
	}

	for _, p := range tl.participants {
		target = p.session
		break
	}
	tl.remote.inboundSeq = relay.Sequence
	tl.markActive()
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
		s.decChat()
		if chat.remoteNode != "" {
			s.sendRemoteTeardown(chat.remoteNode, chat.id, "session_closed")
		}
	}

	s.log.Info("app disconnected", zap.String("session_id", session.id))
}

func (s *AppRouterService) persistChatSecret(chatID string, keys [][]byte) {
	if s.keystore == nil || len(keys) == 0 {
		return
	}
	combined := bytes.Join(keys, []byte(":"))
	defer zeroBytes(combined)
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
	lastSeen     time.Time
	appID        string
}

// chatParticipant wraps per-chat sender state.
type chatParticipant struct {
	session      *appSession
	ephemeralKey []byte
	nextSeq      uint64
	appID        string
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
	remote       *remotePeer
	lastActivity time.Time
	metadata     map[string]string
}

type remotePeer struct {
	nodeID        string
	appID         string
	ephemeralKey  []byte
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

func (t *tieline) addParticipant(p *chatParticipant) error {
	if len(t.participants) >= 2 {
		return errors.New("chat already has two participants")
	}
	if _, ok := t.participants[p.session.id]; ok {
		return errors.New("participant already registered")
	}
	for _, existing := range t.participants {
		if existing.appID != "" && existing.appID == p.appID {
			return errors.New("app already registered in chat")
		}
	}
	t.participants[p.session.id] = p
	return nil
}

func (t *tieline) removeParticipant(sessionID string) {
	if p, ok := t.participants[sessionID]; ok {
		zeroBytes(p.ephemeralKey)
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
	return len(t.participants) == 2
}

func (t *tieline) readyRemote() bool {
	return len(t.participants) == 1 && t.remote != nil && len(t.remote.ephemeralKey) > 0
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
		zeroBytes(p.ephemeralKey)
	}
	if t.remote != nil {
		zeroBytes(t.remote.ephemeralKey)
	}
}

func (t *tieline) participantForApp(appID string) *chatParticipant {
	for _, p := range t.participants {
		if p.appID == appID {
			return p
		}
	}
	return nil
}

func (t *tieline) combinedKeys() [][]byte {
	keys := make([][]byte, 0, len(t.participants)+1)
	for _, p := range t.participants {
		keys = append(keys, append([]byte(nil), p.ephemeralKey...))
	}
	if t.remote != nil && len(t.remote.ephemeralKey) > 0 {
		keys = append(keys, append([]byte(nil), t.remote.ephemeralKey...))
	}
	return keys
}
