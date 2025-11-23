package server

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/hermes-proxy/hermes-proxy/internal/config"
	"github.com/hermes-proxy/hermes-proxy/internal/keystore"
	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// NodeServer wires dependencies and hosts the gRPC server.
type NodeServer struct {
	cfg        config.Config
	log        *zap.Logger
	grpcServer *grpc.Server
	registry   registry.ChatRegistry
	keystore   keystore.KeyBackend
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

	s.grpcServer = grpc.NewServer()
	approuterpb.RegisterAppRouterServer(s.grpcServer, NewAppRouterService(s.log, s.registry, s.keystore))

	go func() {
		<-ctx.Done()
		stopCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownGracePeriod)
		defer cancel()
		s.Shutdown(stopCtx)
	}()

	s.log.Info("gRPC server listening", zap.String("address", s.cfg.GRPCAddress))
	err = s.grpcServer.Serve(lis)
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serve gRPC: %w", err)
	}
	return nil
}

// Shutdown attempts a graceful stop before forcing termination.
func (s *NodeServer) Shutdown(ctx context.Context) {
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
