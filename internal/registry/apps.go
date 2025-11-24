package registry

import (
	"errors"
	"sync"
	"time"
)

// AppPresence tracks a connected app for discovery/routing.
type AppPresence struct {
	AppID       string
	NodeID      string
	SessionID   string
	Metadata    map[string]string
	ConnectedAt time.Time
}

// AppRegistry keeps a map of connected apps.
type AppRegistry interface {
	Register(app AppPresence) error
	Remove(appID string)
	List() []AppPresence
}

// InMemoryAppRegistry stores app presences in a map.
type InMemoryAppRegistry struct {
	mu   sync.RWMutex
	apps map[string]AppPresence
}

// NewAppRegistry builds an in-memory app registry.
func NewAppRegistry() *InMemoryAppRegistry {
	return &InMemoryAppRegistry{
		apps: make(map[string]AppPresence),
	}
}

// Register records an app presence keyed by its identity.
func (r *InMemoryAppRegistry) Register(app AppPresence) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if app.AppID == "" {
		return errors.New("app id is required")
	}
	if app.ConnectedAt.IsZero() {
		app.ConnectedAt = time.Now()
	}
	// clone metadata to avoid external mutation
	cloned := make(map[string]string, len(app.Metadata))
	for k, v := range app.Metadata {
		cloned[k] = v
	}
	app.Metadata = cloned
	r.apps[app.AppID] = app
	return nil
}

// Remove deletes an app presence by identity.
func (r *InMemoryAppRegistry) Remove(appID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.apps, appID)
}

// List enumerates app presences.
func (r *InMemoryAppRegistry) List() []AppPresence {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]AppPresence, 0, len(r.apps))
	for _, app := range r.apps {
		out = append(out, app)
	}
	return out
}
