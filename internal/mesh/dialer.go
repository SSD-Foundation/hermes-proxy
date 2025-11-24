package mesh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Peer describes a bootstrap candidate.
type Peer struct {
	NodeID  string
	Address string
}

// TLSConfig holds TLS materials for node↔node traffic.
type TLSConfig struct {
	Enabled            bool
	CertPath           string
	KeyPath            string
	CAPath             string
	InsecureSkipVerify bool
}

// DialerConfig wires dependencies and cadence for outbound joins.
type DialerConfig struct {
	Log               *zap.Logger
	Store             *Store
	Identity          Identity
	Apps              registry.AppRegistry
	Peers             []Peer
	TLS               TLSConfig
	Interval          time.Duration
	HeartbeatInterval time.Duration
	Metrics           *Metrics
	SuspectAfter      time.Duration
	EvictAfter        time.Duration
	AppSyncInterval   time.Duration
	OnPeerEvicted     func(Member)
	OnPeerSuspect     func(Member)
}

// Dialer attempts to join bootstrap peers and maintain gossip streams.
type Dialer struct {
	log               *zap.Logger
	store             *Store
	identity          Identity
	apps              registry.AppRegistry
	peers             []Peer
	tlsCfg            TLSConfig
	interval          time.Duration
	heartbeatInterval time.Duration
	suspectAfter      time.Duration
	evictAfter        time.Duration
	appSyncInterval   time.Duration
	metrics           *Metrics
	onPeerEvicted     func(Member)
	onPeerSuspect     func(Member)

	mu            sync.Mutex
	gossipStarted map[string]bool
	gossipCh      map[string]chan *nodemeshpb.GossipMessage
	suspected     map[string]bool
}

// NewDialer builds a Dialer.
func NewDialer(cfg DialerConfig) (*Dialer, error) {
	if cfg.Store == nil {
		return nil, errors.New("mesh store is required")
	}
	if cfg.Log == nil {
		cfg.Log = zap.NewNop()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 3 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 10 * time.Second
	}
	if cfg.AppSyncInterval <= 0 {
		cfg.AppSyncInterval = cfg.HeartbeatInterval
	}
	if cfg.SuspectAfter <= 0 {
		cfg.SuspectAfter = 3 * cfg.HeartbeatInterval
	}
	if cfg.EvictAfter <= 0 {
		cfg.EvictAfter = 2 * cfg.SuspectAfter
	}
	return &Dialer{
		log:               cfg.Log,
		store:             cfg.Store,
		identity:          cfg.Identity,
		apps:              cfg.Apps,
		peers:             cfg.Peers,
		tlsCfg:            cfg.TLS,
		interval:          cfg.Interval,
		heartbeatInterval: cfg.HeartbeatInterval,
		suspectAfter:      cfg.SuspectAfter,
		evictAfter:        cfg.EvictAfter,
		appSyncInterval:   cfg.AppSyncInterval,
		metrics:           cfg.Metrics,
		onPeerEvicted:     cfg.OnPeerEvicted,
		onPeerSuspect:     cfg.OnPeerSuspect,
		gossipStarted:     make(map[string]bool),
		gossipCh:          make(map[string]chan *nodemeshpb.GossipMessage),
		suspected:         make(map[string]bool),
	}, nil
}

// Start kicks off periodic join attempts until ctx is canceled.
func (d *Dialer) Start(ctx context.Context) {
	go d.loop(ctx)
	go d.watchdog(ctx)
}

func (d *Dialer) loop(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	d.tryJoin(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.tryJoin(ctx)
		}
	}
}

func (d *Dialer) tryJoin(ctx context.Context) {
	for _, peer := range d.peers {
		if peer.NodeID == "" || peer.Address == "" || peer.NodeID == d.identity.Member.ID {
			continue
		}
		// Skip peers we already know about to avoid noisy reconnects.
		if _, ok := d.store.Member(peer.NodeID); ok {
			d.startGossip(ctx, peer)
			continue
		}

		conn, err := d.dial(ctx, peer.Address)
		if err != nil {
			d.metrics.RecordJoinFailure()
			d.log.Warn("dial bootstrap peer", zap.String("peer", peer.NodeID), zap.String("address", peer.Address), zap.Error(err))
			continue
		}

		client := nodemeshpb.NewNodeMeshClient(conn)
		req := d.joinRequest()
		resp, err := client.Join(ctx, req)
		if err != nil {
			d.metrics.RecordJoinFailure()
			d.log.Warn("join bootstrap peer failed", zap.String("peer", peer.NodeID), zap.Error(err))
			conn.Close()
			continue
		}

		now := time.Now()
		if resp.Self != nil {
			d.store.MergeMembers([]Member{memberFromProto(resp.Self, now)}, now)
		}
		d.store.MergeMembers(protoToMembers(resp.Membership, now), now)
		d.store.MergeApps(normalizeApps(resp.Apps, "", now), now)
		d.store.SetLocalApps(d.localApps(), now)
		d.metrics.RecordJoinSuccess()
		d.metrics.SetKnownNodes(len(d.store.Snapshot()))
		d.log.Info("joined bootstrap peer", zap.String("peer", peer.NodeID), zap.String("address", peer.Address))
		conn.Close()
		d.startGossip(ctx, peer)
	}
}

func (d *Dialer) startGossip(ctx context.Context, peer Peer) {
	d.mu.Lock()
	if d.gossipStarted[peer.NodeID] {
		d.mu.Unlock()
		return
	}
	d.gossipStarted[peer.NodeID] = true
	msgCh := make(chan *nodemeshpb.GossipMessage, 16)
	d.gossipCh[peer.NodeID] = msgCh
	d.mu.Unlock()

	go func() {
		defer func() {
			d.mu.Lock()
			delete(d.gossipCh, peer.NodeID)
			d.mu.Unlock()
		}()
	reconnect:
		for ctx.Err() == nil {
			conn, err := d.dial(ctx, peer.Address)
			if err != nil {
				d.log.Warn("gossip dial failed", zap.String("peer", peer.NodeID), zap.Error(err))
				time.Sleep(d.interval)
				continue
			}

			client := nodemeshpb.NewNodeMeshClient(conn)
			stream, err := client.Gossip(ctx)
			if err != nil {
				d.log.Warn("open gossip stream", zap.String("peer", peer.NodeID), zap.Error(err))
				conn.Close()
				time.Sleep(d.interval)
				continue
			}

			ticker := time.NewTicker(d.heartbeatInterval)
			appTicker := time.NewTicker(d.appSyncInterval)
			for {
				select {
				case <-ctx.Done():
					ticker.Stop()
					appTicker.Stop()
					conn.Close()
					return
				case <-ticker.C:
					hb := &nodemeshpb.GossipMessage{
						Body: &nodemeshpb.GossipMessage_Heartbeat{
							Heartbeat: &nodemeshpb.Heartbeat{
								Node:           descriptorFromMember(d.identity.Member),
								TimestampNanos: time.Now().UnixNano(),
							},
						},
					}
					if err := stream.Send(hb); err != nil {
						if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
							d.log.Warn("send heartbeat failed", zap.String("peer", peer.NodeID), zap.Error(err))
						}
						ticker.Stop()
						appTicker.Stop()
						conn.Close()
						time.Sleep(d.interval)
						continue reconnect
					}
				case <-appTicker.C:
					if msg := d.buildAppSync(); msg != nil {
						if err := stream.Send(msg); err != nil {
							if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
								d.log.Warn("send app sync failed", zap.String("peer", peer.NodeID), zap.Error(err))
							}
							ticker.Stop()
							appTicker.Stop()
							conn.Close()
							time.Sleep(d.interval)
							continue reconnect
						}
					}
				case msg, ok := <-msgCh:
					if !ok {
						ticker.Stop()
						appTicker.Stop()
						conn.Close()
						return
					}
					if err := stream.Send(msg); err != nil {
						if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
							d.log.Warn("send gossip message failed", zap.String("peer", peer.NodeID), zap.Error(err))
						}
						ticker.Stop()
						appTicker.Stop()
						conn.Close()
						time.Sleep(d.interval)
						continue reconnect
					}
				}
			}
		}
	}()
}

func (d *Dialer) dial(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	opt, err := d.transportCredentials()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.interval)
	defer cancel()
	return grpc.DialContext(ctx, addr, opt)
}

func (d *Dialer) transportCredentials() (grpc.DialOption, error) {
	return dialTransportOption(d.tlsCfg)
}

func (d *Dialer) joinRequest() *nodemeshpb.JoinRequest {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)

	desc := descriptorFromMember(d.identity.Member)
	sig := ed25519.Sign(d.identity.PrivateKey, joinPayload(desc, nonce))
	return &nodemeshpb.JoinRequest{
		Node:      desc,
		Nonce:     nonce,
		Signature: sig,
		Apps:      appsToProto(d.localApps()),
	}
}

func (d *Dialer) localApps() []registry.AppPresence {
	if d.apps == nil {
		return nil
	}
	return d.apps.List()
}

func protoToMembers(p []*nodemeshpb.NodeDescriptor, now time.Time) []Member {
	out := make([]Member, 0, len(p))
	for _, m := range p {
		if m == nil {
			continue
		}
		out = append(out, memberFromProto(m, now))
	}
	return out
}

func (d *Dialer) buildAppSync() *nodemeshpb.GossipMessage {
	apps := d.localApps()
	if len(apps) == 0 {
		return nil
	}
	return &nodemeshpb.GossipMessage{
		Body: &nodemeshpb.GossipMessage_AppSync{
			AppSync: &nodemeshpb.AppSync{
				NodeId: d.identity.Member.ID,
				Apps:   appsToProto(apps),
			},
		},
	}
}

func (d *Dialer) broadcast(msg *nodemeshpb.GossipMessage) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for nodeID, ch := range d.gossipCh {
		select {
		case ch <- msg:
		default:
			d.log.Warn("gossip channel full, dropping update", zap.String("peer", nodeID))
		}
	}
}

func (d *Dialer) watchdog(ctx context.Context) {
	if d.evictAfter <= 0 {
		return
	}
	ticker := time.NewTicker(d.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			current := make(map[string]struct{})
			for _, member := range d.store.Snapshot() {
				if member.ID == d.identity.Member.ID {
					continue
				}
				current[member.ID] = struct{}{}
				elapsed := now.Sub(member.LastSeen)
				if elapsed > d.suspectAfter {
					if !d.suspected[member.ID] {
						d.suspected[member.ID] = true
						d.log.Warn("peer suspected", zap.String("node_id", member.ID), zap.Duration("last_seen_ago", elapsed))
						if d.onPeerSuspect != nil {
							d.onPeerSuspect(member)
						}
					}
				} else {
					delete(d.suspected, member.ID)
				}
			}
			for id := range d.suspected {
				if _, ok := current[id]; !ok {
					delete(d.suspected, id)
				}
			}
			for _, started := range d.startedPeers() {
				if started == d.identity.Member.ID {
					continue
				}
				if _, ok := current[started]; !ok {
					d.stopGossip(started)
				}
			}

			cutoff := now.Add(-d.evictAfter)
			removed := d.store.EvictStale(cutoff)
			if len(removed) == 0 {
				d.metrics.SetSuspectedPeers(len(d.suspected))
				continue
			}
			for _, member := range removed {
				delete(d.suspected, member.ID)
				d.log.Warn("evicted stale peer", zap.String("node_id", member.ID))
				d.stopGossip(member.ID)
				d.broadcast(&nodemeshpb.GossipMessage{
					Body: &nodemeshpb.GossipMessage_Membership{
						Membership: &nodemeshpb.MembershipEvent{
							Type: nodemeshpb.MembershipEvent_TYPE_FAIL,
							Node: descriptorFromMember(member),
						},
					},
				})
				if d.onPeerEvicted != nil {
					d.onPeerEvicted(member)
				}
				d.metrics.RecordEvictedPeer()
			}
			d.metrics.SetKnownNodes(len(d.store.Snapshot()))
			d.metrics.SetSuspectedPeers(len(d.suspected))
		}
	}
}

func (d *Dialer) stopGossip(nodeID string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if ch, ok := d.gossipCh[nodeID]; ok {
		close(ch)
		delete(d.gossipCh, nodeID)
	}
	d.gossipStarted[nodeID] = false
}

func (d *Dialer) startedPeers() []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]string, 0, len(d.gossipStarted))
	for id := range d.gossipStarted {
		out = append(out, id)
	}
	return out
}
