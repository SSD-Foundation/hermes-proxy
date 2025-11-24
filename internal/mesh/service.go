package mesh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Service implements the NodeMesh gRPC contract.
type Service struct {
	nodemeshpb.UnimplementedNodeMeshServer
	log     *zap.Logger
	store   *Store
	metrics *Metrics
	apps    registry.AppRegistry
	self    Identity
	router  RouteHandler
}

// ServiceConfig wires dependencies for the NodeMesh service.
type ServiceConfig struct {
	Log      *zap.Logger
	Store    *Store
	Metrics  *Metrics
	Apps     registry.AppRegistry
	Identity Identity
	Router   RouteHandler
}

// NewService constructs the NodeMesh service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("mesh store is required")
	}
	if cfg.Log == nil {
		cfg.Log = zap.NewNop()
	}
	if len(cfg.Identity.PrivateKey) == 0 || len(cfg.Identity.Member.IdentityKey) == 0 {
		return nil, errors.New("mesh identity keys are required")
	}
	return &Service{
		log:     cfg.Log,
		store:   cfg.Store,
		metrics: cfg.Metrics,
		apps:    cfg.Apps,
		self:    cfg.Identity,
		router:  cfg.Router,
	}, nil
}

// Join authenticates the peer, records membership, and returns a snapshot.
func (s *Service) Join(ctx context.Context, req *nodemeshpb.JoinRequest) (*nodemeshpb.JoinResponse, error) {
	if req == nil || req.Node == nil {
		return nil, status.Error(codes.InvalidArgument, "node descriptor required")
	}
	if err := validateDescriptor(req.Node); err != nil {
		s.metrics.RecordJoinFailure()
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if len(req.Signature) == 0 {
		s.metrics.RecordJoinFailure()
		return nil, status.Error(codes.Unauthenticated, "join signature required")
	}
	payload := joinPayload(req.Node, req.Nonce)
	if !ed25519.Verify(ed25519.PublicKey(req.Node.IdentityKey), payload, req.Signature) {
		s.metrics.RecordJoinFailure()
		return nil, status.Error(codes.Unauthenticated, "join signature invalid")
	}

	now := time.Now()
	member := memberFromProto(req.Node, now)
	s.store.MergeMembers([]Member{member}, now)

	apps := normalizeApps(req.Apps, member.ID, now)
	if len(apps) > 0 {
		s.store.MergeApps(apps, now)
	}

	localApps := s.localApps()
	if len(localApps) > 0 {
		s.store.SetLocalApps(localApps, now)
	}

	s.metrics.RecordJoinSuccess()
	s.metrics.SetKnownNodes(len(s.store.Snapshot()))
	s.log.Info("accepted join", zap.String("node_id", member.ID), zap.String("endpoint", member.Endpoint))

	resp := &nodemeshpb.JoinResponse{
		Self:       descriptorFromMember(s.self.Member),
		Membership: membersToProto(s.store.Snapshot()),
		Apps:       appsToProto(s.store.Apps()),
	}
	return resp, nil
}

// Gossip ingests membership heartbeats and app sync frames.
func (s *Service) Gossip(stream nodemeshpb.NodeMesh_GossipServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}

		switch body := msg.Body.(type) {
		case *nodemeshpb.GossipMessage_Heartbeat:
			if body.Heartbeat == nil || body.Heartbeat.Node == nil {
				continue
			}
			if err := validateDescriptor(body.Heartbeat.Node); err != nil {
				continue
			}
			ts := time.Unix(0, body.Heartbeat.TimestampNanos)
			if ts.IsZero() {
				ts = time.Now()
			}
			s.store.Upsert(memberFromProto(body.Heartbeat.Node, ts), ts)
			s.metrics.RecordHeartbeat()
			s.metrics.SetKnownNodes(len(s.store.Snapshot()))
		case *nodemeshpb.GossipMessage_Membership:
			if body.Membership == nil || body.Membership.Node == nil {
				continue
			}
			if err := validateDescriptor(body.Membership.Node); err != nil {
				continue
			}
			now := time.Now()
			s.store.Upsert(memberFromProto(body.Membership.Node, now), now)
			s.metrics.SetKnownNodes(len(s.store.Snapshot()))
		case *nodemeshpb.GossipMessage_AppSync:
			if body.AppSync == nil {
				continue
			}
			now := time.Now()
			changes := s.store.MergeApps(normalizeApps(body.AppSync.GetApps(), body.AppSync.GetNodeId(), now), now)
			if changes > 0 {
				s.metrics.RecordAppSync()
			}
		}
	}
}

// RouteChat is not yet implemented in iteration 01.
func (s *Service) RouteChat(stream nodemeshpb.NodeMesh_RouteChatServer) error {
	if s.router == nil {
		return status.Error(codes.Unimplemented, "route handler not configured")
	}

	ctx := stream.Context()
	peerNode := peerNodeFromContext(ctx)
	defer s.router.HandleRouteClosed(peerNode)

	for {
		frame, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		if peerNode == "" {
			if setup := frame.GetSetupTieline(); setup != nil && setup.SourceNodeId != "" {
				peerNode = setup.SourceNodeId
			}
		}

		resp, handleErr := s.router.HandleRouteFrame(ctx, peerNode, frame)
		if handleErr != nil {
			var rerr *RouteError
			if errors.As(handleErr, &rerr) {
				_ = stream.Send(&nodemeshpb.RouteFrame{
					CorrelationId: frame.GetCorrelationId(),
					Body: &nodemeshpb.RouteFrame_Error{
						Error: &nodemeshpb.RouteError{Code: rerr.Code, Message: rerr.Msg},
					},
				})
				if rerr.Fatal {
					return status.Error(codes.PermissionDenied, rerr.Msg)
				}
				continue
			}
			return handleErr
		}

		if resp != nil {
			if resp.CorrelationId == "" {
				resp.CorrelationId = frame.GetCorrelationId()
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// AttachRouter wires the RouteChat handler after construction.
func (s *Service) AttachRouter(handler RouteHandler) {
	s.router = handler
}

func peerNodeFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("node-id"); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func validateDescriptor(node *nodemeshpb.NodeDescriptor) error {
	if node == nil {
		return errors.New("node descriptor required")
	}
	if node.NodeId == "" {
		return errors.New("node id required")
	}
	if node.Endpoint == "" {
		return errors.New("endpoint required")
	}
	if len(node.IdentityKey) != ed25519.PublicKeySize {
		return fmt.Errorf("identity key must be %d bytes", ed25519.PublicKeySize)
	}
	return nil
}

func joinPayload(node *nodemeshpb.NodeDescriptor, nonce []byte) []byte {
	buf := bytes.Buffer{}
	buf.WriteString(node.NodeId)
	buf.WriteString(node.Endpoint)
	buf.Write(nonce)

	keys := make([]string, 0, len(node.Metadata))
	for k := range node.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteString(node.Metadata[k])
	}
	return buf.Bytes()
}

func membersToProto(members []Member) []*nodemeshpb.NodeDescriptor {
	out := make([]*nodemeshpb.NodeDescriptor, 0, len(members))
	for _, m := range members {
		out = append(out, descriptorFromMember(m))
	}
	return out
}

func descriptorFromMember(m Member) *nodemeshpb.NodeDescriptor {
	return &nodemeshpb.NodeDescriptor{
		NodeId:      m.ID,
		Endpoint:    m.Endpoint,
		IdentityKey: append([]byte(nil), m.IdentityKey...),
		Wallet:      m.Wallet,
		Metadata:    cloneMetadata(m.Metadata),
	}
}

func memberFromProto(nd *nodemeshpb.NodeDescriptor, lastSeen time.Time) Member {
	return Member{
		ID:          nd.GetNodeId(),
		Endpoint:    nd.GetEndpoint(),
		IdentityKey: append([]byte(nil), nd.GetIdentityKey()...),
		Wallet:      nd.GetWallet(),
		Metadata:    cloneMetadata(nd.GetMetadata()),
		LastSeen:    lastSeen,
	}
}

func normalizeApps(apps []*nodemeshpb.AppRegistration, nodeID string, now time.Time) []registry.AppPresence {
	out := make([]registry.AppPresence, 0, len(apps))
	for _, app := range apps {
		if app == nil {
			continue
		}
		appID := app.AppId
		if appID == "" {
			continue
		}
		host := app.NodeId
		if host == "" {
			host = nodeID
		}
		connected := time.Unix(0, app.ConnectedAtNanos)
		if connected.IsZero() {
			connected = now
		}
		out = append(out, registry.AppPresence{
			AppID:       appID,
			NodeID:      host,
			SessionID:   app.SessionId,
			Metadata:    cloneMetadata(app.Metadata),
			ConnectedAt: connected,
		})
	}
	return out
}

func appsToProto(apps []registry.AppPresence) []*nodemeshpb.AppRegistration {
	out := make([]*nodemeshpb.AppRegistration, 0, len(apps))
	for _, app := range apps {
		out = append(out, &nodemeshpb.AppRegistration{
			AppId:            app.AppID,
			NodeId:           app.NodeID,
			SessionId:        app.SessionID,
			Metadata:         cloneMetadata(app.Metadata),
			ConnectedAtNanos: app.ConnectedAt.UnixNano(),
		})
	}
	return out
}

func (s *Service) localApps() []registry.AppPresence {
	if s.apps == nil {
		return nil
	}
	return s.apps.List()
}
