package server

import (
	"context"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
	"github.com/hermes-proxy/hermes-proxy/pkg/api/approuterpb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AppRouterService implements the gRPC AppRouter contract.
type AppRouterService struct {
	approuterpb.UnimplementedAppRouterServer
	log      *zap.Logger
	registry registry.ChatRegistry
}

// NewAppRouterService returns a placeholder AppRouter implementation.
func NewAppRouterService(log *zap.Logger, reg registry.ChatRegistry) *AppRouterService {
	if reg == nil {
		reg = registry.NewInMemory(0)
	}
	return &AppRouterService{
		log:      log,
		registry: reg,
	}
}

// Open is a stub handler for iteration 01; it simply rejects calls.
func (s *AppRouterService) Open(stream approuterpb.AppRouter_OpenServer) error {
	s.log.Info("AppRouter.Open called (stub)")
	return status.Error(codes.Unimplemented, "AppRouter.Open not implemented in iteration 01")
}

// placeholder to keep the interface used for future interceptors/tests.
func (s *AppRouterService) openStream(_ context.Context) error {
	return status.Error(codes.Unimplemented, "stream handling not implemented")
}
