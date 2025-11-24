package mesh

import (
	"context"

	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
)

// RouteHandler processes NodeMesh RouteChat frames and coordinates routing.
type RouteHandler interface {
	HandleRouteFrame(ctx context.Context, fromNode string, frame *nodemeshpb.RouteFrame) (*nodemeshpb.RouteFrame, error)
	HandleRouteClosed(nodeID string)
}

// RouteError maps validation failures to wire errors.
type RouteError struct {
	Code  string
	Msg   string
	Fatal bool
}

func (e *RouteError) Error() string {
	return e.Msg
}
