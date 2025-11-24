package mesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/hermes-proxy/hermes-proxy/pkg/api/nodemeshpb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// RouteClientConfig seeds the outbound RouteChat pool.
type RouteClientConfig struct {
	Log         *zap.Logger
	Store       *Store
	TLS         TLSConfig
	Handler     RouteHandler
	NodeID      string
	DialTimeout time.Duration
}

// RouteClientPool maintains RouteChat streams keyed by node ID.
type RouteClientPool struct {
	log         *zap.Logger
	store       *Store
	tlsCfg      TLSConfig
	handler     RouteHandler
	nodeID      string
	dialTimeout time.Duration

	mu      sync.Mutex
	clients map[string]*routeClient
}

// NewRouteClientPool builds a pool of outbound RouteChat streams.
func NewRouteClientPool(cfg RouteClientConfig) (*RouteClientPool, error) {
	if cfg.Store == nil {
		return nil, errors.New("mesh store is required")
	}
	if cfg.Handler == nil {
		return nil, errors.New("route handler is required")
	}
	if cfg.Log == nil {
		cfg.Log = zap.NewNop()
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}

	return &RouteClientPool{
		log:         cfg.Log,
		store:       cfg.Store,
		tlsCfg:      cfg.TLS,
		handler:     cfg.Handler,
		nodeID:      cfg.NodeID,
		dialTimeout: cfg.DialTimeout,
		clients:     make(map[string]*routeClient),
	}, nil
}

// Send pushes a RouteFrame to the target node, establishing a stream if needed.
func (p *RouteClientPool) Send(ctx context.Context, nodeID string, frame *nodemeshpb.RouteFrame) error {
	client, err := p.ensureClient(ctx, nodeID)
	if err != nil {
		return err
	}
	return client.send(frame)
}

// Close tears down the stream to a peer, if present.
func (p *RouteClientPool) Close(nodeID string) {
	p.mu.Lock()
	client := p.clients[nodeID]
	p.mu.Unlock()

	if client != nil {
		client.close()
	}
}

func (p *RouteClientPool) ensureClient(ctx context.Context, nodeID string) (*routeClient, error) {
	p.mu.Lock()
	if client, ok := p.clients[nodeID]; ok {
		p.mu.Unlock()
		return client, nil
	}
	p.mu.Unlock()

	member, ok := p.store.Member(nodeID)
	if !ok {
		return nil, fmt.Errorf("route target %s not found", nodeID)
	}

	opt, err := dialTransportOption(p.tlsCfg)
	if err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, member.Endpoint, opt)
	if err != nil {
		return nil, fmt.Errorf("dial route peer %s: %w", nodeID, err)
	}

	mdCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("node-id", p.nodeID))
	stream, err := nodemeshpb.NewNodeMeshClient(conn).RouteChat(mdCtx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open route stream to %s: %w", nodeID, err)
	}

	rcCtx, cancelFunc := context.WithCancel(context.Background())
	client := &routeClient{
		nodeID:  nodeID,
		conn:    conn,
		stream:  stream,
		handler: p.handler,
		log:     p.log,
		onClose: func() { p.drop(nodeID) },
		ctx:     rcCtx,
		cancel:  cancelFunc,
		sendCh:  make(chan *nodemeshpb.RouteFrame, 32),
	}
	client.start()

	p.mu.Lock()
	p.clients[nodeID] = client
	p.mu.Unlock()
	return client, nil
}

func (p *RouteClientPool) drop(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.clients, nodeID)
}

type routeClient struct {
	nodeID   string
	conn     *grpc.ClientConn
	stream   nodemeshpb.NodeMesh_RouteChatClient
	handler  RouteHandler
	log      *zap.Logger
	onClose  func()
	ctx      context.Context
	cancel   context.CancelFunc
	sendCh   chan *nodemeshpb.RouteFrame
	shutdown chan struct{}
	once     sync.Once
}

func (c *routeClient) start() {
	go c.sendLoop()
	go c.recvLoop()
}

func (c *routeClient) send(frame *nodemeshpb.RouteFrame) error {
	select {
	case <-c.ctx.Done():
		return errors.New("route stream closed")
	case c.sendCh <- frame:
		return nil
	default:
		return errors.New("route stream backpressure")
	}
}

func (c *routeClient) sendLoop() {
	defer c.close()
	for {
		select {
		case <-c.ctx.Done():
			return
		case frame := <-c.sendCh:
			if frame == nil {
				return
			}
			if err := c.stream.Send(frame); err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
					c.log.Warn("route send failed", zap.String("peer", c.nodeID), zap.Error(err))
				}
				return
			}
		}
	}
}

func (c *routeClient) recvLoop() {
	defer c.close()
	for {
		frame, err := c.stream.Recv()
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				c.log.Warn("route recv failed", zap.String("peer", c.nodeID), zap.Error(err))
			}
			return
		}

		resp, handleErr := c.handler.HandleRouteFrame(c.ctx, c.nodeID, frame)
		if handleErr != nil {
			var rerr *RouteError
			if errors.As(handleErr, &rerr) {
				select {
				case c.sendCh <- &nodemeshpb.RouteFrame{
					CorrelationId: frame.GetCorrelationId(),
					Body: &nodemeshpb.RouteFrame_Error{
						Error: &nodemeshpb.RouteError{Code: rerr.Code, Message: rerr.Msg},
					},
				}:
				case <-c.ctx.Done():
				default:
					c.log.Warn("route send buffer full while reporting error", zap.String("peer", c.nodeID))
				}
				if rerr.Fatal {
					return
				}
				continue
			}
			c.log.Warn("route handler failed", zap.String("peer", c.nodeID), zap.Error(handleErr))
			return
		}

		if resp != nil {
			if resp.CorrelationId == "" {
				resp.CorrelationId = frame.GetCorrelationId()
			}
			select {
			case c.sendCh <- resp:
			case <-c.ctx.Done():
				return
			default:
				c.log.Warn("route send buffer full while replying", zap.String("peer", c.nodeID))
				return
			}
		}
	}
}

func (c *routeClient) close() {
	c.once.Do(func() {
		c.cancel()
		if c.handler != nil {
			c.handler.HandleRouteClosed(c.nodeID)
		}
		if c.onClose != nil {
			c.onClose()
		}
		if c.conn != nil {
			c.conn.Close()
		}
	})
}
