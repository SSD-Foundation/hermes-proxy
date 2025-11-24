package mesh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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
	metrics           *Metrics

	mu            sync.Mutex
	gossipStarted map[string]bool
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
	return &Dialer{
		log:               cfg.Log,
		store:             cfg.Store,
		identity:          cfg.Identity,
		apps:              cfg.Apps,
		peers:             cfg.Peers,
		tlsCfg:            cfg.TLS,
		interval:          cfg.Interval,
		heartbeatInterval: cfg.HeartbeatInterval,
		metrics:           cfg.Metrics,
		gossipStarted:     make(map[string]bool),
	}, nil
}

// Start kicks off periodic join attempts until ctx is canceled.
func (d *Dialer) Start(ctx context.Context) {
	go d.loop(ctx)
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
	d.mu.Unlock()

	go func() {
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
			for {
				select {
				case <-ctx.Done():
					ticker.Stop()
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
	if !d.tlsCfg.Enabled {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}

	if d.tlsCfg.CertPath == "" || d.tlsCfg.KeyPath == "" {
		return nil, errors.New("tls enabled but cert/key paths are empty")
	}
	cert, err := tls.LoadX509KeyPair(d.tlsCfg.CertPath, d.tlsCfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load mesh tls cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: d.tlsCfg.InsecureSkipVerify,
	}
	if d.tlsCfg.CAPath != "" {
		pool := x509.NewCertPool()
		caBytes, err := os.ReadFile(d.tlsCfg.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read mesh ca: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("append mesh ca cert failed")
		}
		tlsCfg.RootCAs = pool
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), nil
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
