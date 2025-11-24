package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/config"
	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/mesh"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// NodeServer wires dependencies and hosts the gRPC server.
type NodeServer struct {
	cfg         config.Config
	log         *zap.Logger
	grpcServer  *grpc.Server
	registry    registry.ChatRegistry
	apps        registry.AppRegistry
	keystore    keystore.KeyBackend
	adminHTTP   *http.Server
	metrics     *routerMetrics
	meshMetrics *mesh.Metrics
	meshStore   *mesh.Store
	meshSvc     *mesh.Service
	meshDialer  *mesh.Dialer
	routes      *mesh.RouteClientPool
	identity    mesh.Identity
	router      *AppRouterService
	ready       atomic.Bool
}

// NewNodeServer constructs a server with its dependencies.
func NewNodeServer(cfg config.Config, logger *zap.Logger, reg registry.ChatRegistry, ks keystore.KeyBackend) *NodeServer {
	if reg == nil {
		reg = registry.NewInMemory(0)
	}
	return &NodeServer{
		cfg:      cfg,
		log:      logger,
		registry: reg,
		apps:     registry.NewAppRegistry(),
		keystore: ks,
	}
}

// Start boots the gRPC server and blocks until shutdown.
func (s *NodeServer) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.cfg.GRPCAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.GRPCAddress, err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	s.metrics = newRouterMetrics(reg)
	s.meshMetrics = mesh.NewMetrics(reg)

	if err := s.initMesh(ctx); err != nil {
		return err
	}
	s.startAdminServer(reg)

	grpcOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    s.cfg.GRPCServer.KeepaliveTime,
			Timeout: s.cfg.GRPCServer.KeepaliveTimeout,
			// MaxConnectionIdle forces hung streams to disconnect and re-auth.
			MaxConnectionIdle: s.cfg.GRPCServer.MaxConnectionIdle,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             s.cfg.GRPCServer.KeepaliveTime / 2,
			PermitWithoutStream: true,
		}),
		grpc.MaxRecvMsgSize(s.cfg.GRPCServer.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.cfg.GRPCServer.MaxSendMsgSize),
	}
	if cred, err := s.serverTLSOption(); err != nil {
		return err
	} else if cred != nil {
		grpcOpts = append(grpcOpts, cred)
	}

	s.grpcServer = grpc.NewServer(grpcOpts...)
	router := NewAppRouterService(s.log, s.registry, s.keystore, RouterOptions{
		Metrics:              s.metrics,
		SessionIdleTimeout:   s.cfg.Cleanup.SessionIdleTimeout,
		ChatIdleTimeout:      s.cfg.Cleanup.ChatIdleTimeout,
		HousekeepingInterval: s.cfg.Cleanup.SweepInterval,
		NodeID:               s.cfg.Mesh.NodeID,
		Apps:                 s.apps,
		MeshStore:            s.meshStore,
	})
	s.router = router

	routePool, err := mesh.NewRouteClientPool(mesh.RouteClientConfig{
		Log:         s.log,
		Store:       s.meshStore,
		TLS:         meshTLSFromConfig(s.cfg.Mesh.TLS),
		Handler:     router,
		NodeID:      s.cfg.Mesh.NodeID,
		DialTimeout: s.cfg.Mesh.Gossip.DialInterval,
	})
	if err != nil {
		return fmt.Errorf("init route pool: %w", err)
	}
	s.routes = routePool
	router.routes = routePool
	router.store = s.meshStore
	if s.meshSvc != nil {
		s.meshSvc.AttachRouter(router)
	}

	router.StartHousekeeping(ctx)
	approuterpb.RegisterAppRouterServer(s.grpcServer, router)
	nodemeshpb.RegisterNodeMeshServer(s.grpcServer, s.meshSvc)

	go func() {
		<-ctx.Done()
		stopCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGracePeriod)
		defer cancel()
		s.Shutdown(stopCtx)
	}()

	s.log.Info("gRPC server listening", zap.String("address", s.cfg.GRPCAddress))
	s.ready.Store(true)
	s.meshDialer.Start(ctx)
	err = s.grpcServer.Serve(lis)
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve gRPC: %w", err)
	}
	return nil
}

func (s *NodeServer) initMesh(ctx context.Context) error {
	pub, priv, err := mesh.EnsureIdentityKey(ctx, s.keystore, s.cfg.Mesh.IdentitySecret)
	if err != nil {
		return fmt.Errorf("init mesh identity: %w", err)
	}

	endpoint := s.cfg.Mesh.PublicAddress
	if endpoint == "" {
		endpoint = s.cfg.GRPCAddress
	}

	selfMember := mesh.Member{
		ID:          s.cfg.Mesh.NodeID,
		Endpoint:    endpoint,
		IdentityKey: pub,
		Wallet:      s.cfg.Mesh.Wallet,
		Metadata: map[string]string{
			"grpc_address": s.cfg.GRPCAddress,
		},
		LastSeen: time.Now(),
	}

	store, err := mesh.NewStore(selfMember)
	if err != nil {
		return fmt.Errorf("init mesh store: %w", err)
	}
	store.SetLocalApps(s.apps.List(), time.Now())
	s.meshStore = store
	s.identity = mesh.Identity{Member: selfMember, PrivateKey: priv}
	s.meshMetrics.SetKnownNodes(len(store.Snapshot()))

	svc, err := mesh.NewService(mesh.ServiceConfig{
		Log:           s.log,
		Store:         store,
		Metrics:       s.meshMetrics,
		Apps:          s.apps,
		Identity:      s.identity,
		OnPeerRemoved: s.handlePeerEvicted,
	})
	if err != nil {
		return fmt.Errorf("init mesh service: %w", err)
	}
	s.meshSvc = svc

	dialer, err := mesh.NewDialer(mesh.DialerConfig{
		Log:               s.log,
		Store:             store,
		Identity:          s.identity,
		Apps:              s.apps,
		Peers:             peersFromConfig(s.cfg.Mesh.BootstrapPeers),
		TLS:               meshTLSFromConfig(s.cfg.Mesh.TLS),
		Interval:          s.cfg.Mesh.Gossip.DialInterval,
		HeartbeatInterval: s.cfg.Mesh.Gossip.HeartbeatInterval,
		Metrics:           s.meshMetrics,
		OnPeerEvicted:     s.handlePeerEvicted,
	})
	if err != nil {
		return fmt.Errorf("init mesh dialer: %w", err)
	}
	s.meshDialer = dialer
	return nil
}

func (s *NodeServer) serverTLSOption() (grpc.ServerOption, error) {
	if !s.cfg.Mesh.TLS.Enabled {
		return nil, nil
	}
	if s.cfg.Mesh.TLS.CertPath == "" || s.cfg.Mesh.TLS.KeyPath == "" {
		return nil, fmt.Errorf("mesh.tls.enabled but cert/key are empty")
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.Mesh.TLS.CertPath, s.cfg.Mesh.TLS.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load mesh tls cert/key: %w", err)
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if s.cfg.Mesh.TLS.CAPath != "" {
		pool := x509.NewCertPool()
		caBytes, err := os.ReadFile(s.cfg.Mesh.TLS.CAPath)
		if err != nil {
			return nil, fmt.Errorf("read mesh ca: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, errors.New("append mesh ca failed")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return grpc.Creds(credentials.NewTLS(tlsCfg)), nil
}

func (s *NodeServer) startAdminServer(reg *prometheus.Registry) {
	if s.cfg.Admin.Address == "" {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not_ready"))
	})
	if s.meshStore != nil {
		mux.HandleFunc("/mesh/members", func(w http.ResponseWriter, _ *http.Request) {
			payload := struct {
				Nodes []mesh.Member          `json:"nodes"`
				Apps  []registry.AppPresence `json:"apps"`
			}{
				Nodes: s.meshStore.Snapshot(),
				Apps:  s.meshStore.Apps(),
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(payload); err != nil {
				s.log.Warn("encode mesh membership", zap.Error(err))
			}
		})
	}

	s.adminHTTP = &http.Server{
		Addr:              s.cfg.Admin.Address,
		Handler:           mux,
		ReadHeaderTimeout: s.cfg.Admin.ReadHeaderTimeout,
	}

	go func() {
		if err := s.adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Warn("admin server stopped", zap.Error(err))
		}
	}()
	s.log.Info("admin server listening", zap.String("address", s.cfg.Admin.Address))
}

func meshTLSFromConfig(cfg config.MeshTLS) mesh.TLSConfig {
	return mesh.TLSConfig{
		Enabled:            cfg.Enabled,
		CertPath:           cfg.CertPath,
		KeyPath:            cfg.KeyPath,
		CAPath:             cfg.CAPath,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
}

func peersFromConfig(in []config.MeshPeer) []mesh.Peer {
	out := make([]mesh.Peer, 0, len(in))
	for _, p := range in {
		if p.Address == "" || p.NodeID == "" {
			continue
		}
		out = append(out, mesh.Peer{NodeID: p.NodeID, Address: p.Address})
	}
	return out
}

// Shutdown attempts a graceful stop before forcing termination.
func (s *NodeServer) Shutdown(ctx context.Context) {
	s.ready.Store(false)

	if s.adminHTTP != nil {
		if err := s.adminHTTP.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Warn("admin server shutdown", zap.Error(err))
		}
	}
	if s.grpcServer == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		s.log.Info("gRPC server stopped")
	case <-ctx.Done():
		s.log.Warn("graceful shutdown timed out; forcing stop")
		s.grpcServer.Stop()
	}
}

func (s *NodeServer) handlePeerEvicted(member mesh.Member) {
	if member.ID == "" {
		return
	}
	s.log.Warn("peer evicted, cleaning up routes", zap.String("node_id", member.ID))
	if s.routes != nil {
		s.routes.Close(member.ID)
	}
	if s.router != nil {
		s.router.handleNodeLoss(member.ID, "route_unavailable")
	}
}
