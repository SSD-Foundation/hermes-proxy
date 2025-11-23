package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/hermes-proxy/hermes-proxy/internal/config"
	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// NodeServer wires dependencies and hosts the gRPC server.
type NodeServer struct {
	cfg        config.Config
	log        *zap.Logger
	grpcServer *grpc.Server
	registry   registry.ChatRegistry
	keystore   keystore.KeyBackend
	adminHTTP  *http.Server
	metrics    *routerMetrics
	ready      atomic.Bool
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

	s.grpcServer = grpc.NewServer(grpcOpts...)
	router := NewAppRouterService(s.log, s.registry, s.keystore, RouterOptions{
		Metrics:              s.metrics,
		SessionIdleTimeout:   s.cfg.Cleanup.SessionIdleTimeout,
		ChatIdleTimeout:      s.cfg.Cleanup.ChatIdleTimeout,
		HousekeepingInterval: s.cfg.Cleanup.SweepInterval,
	})
	router.StartHousekeeping(ctx)
	approuterpb.RegisterAppRouterServer(s.grpcServer, router)

	go func() {
		<-ctx.Done()
		stopCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGracePeriod)
		defer cancel()
		s.Shutdown(stopCtx)
	}()

	s.log.Info("gRPC server listening", zap.String("address", s.cfg.GRPCAddress))
	s.ready.Store(true)
	err = s.grpcServer.Serve(lis)
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve gRPC: %w", err)
	}
	return nil
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
