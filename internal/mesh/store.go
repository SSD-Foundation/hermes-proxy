package mesh

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/hermes-proxy/hermes-proxy/internal/registry"
)

// Member captures node identity and last observed heartbeat.
type Member struct {
	ID          string
	Endpoint    string
	IdentityKey []byte
	Wallet      string
	Metadata    map[string]string
	LastSeen    time.Time
}

// Store maintains membership and app presence information.
type Store struct {
	self    Member
	mu      sync.RWMutex
	members map[string]Member
	apps    map[string]registry.AppPresence
}

// NewStore seeds the store with the current node identity.
func NewStore(self Member) (*Store, error) {
	if self.ID == "" {
		return nil, errors.New("self node id is required")
	}
	if self.LastSeen.IsZero() {
		self.LastSeen = time.Now()
	}
	s := &Store{
		self:    cloneMember(self),
		members: make(map[string]Member),
		apps:    make(map[string]registry.AppPresence),
	}
	s.members[self.ID] = cloneMember(self)
	return s, nil
}

// Self returns the node's own member record.
func (s *Store) Self() Member {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneMember(s.self)
}

// Snapshot returns all known members (including self).
func (s *Store) Snapshot() []Member {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Member, 0, len(s.members))
	for _, m := range s.members {
		out = append(out, cloneMember(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Member fetches a member by node ID.
func (s *Store) Member(id string) (Member, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.members[id]
	return cloneMember(m), ok
}

// Upsert inserts or updates a member record and stamps lastSeen.
func (s *Store) Upsert(member Member, now time.Time) (Member, bool) {
	if member.ID == "" {
		return Member{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	member.LastSeen = now

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.members[member.ID]
	normalized := cloneMember(member)
	changed := !ok || !memberEqual(existing, normalized)
	if changed {
		s.members[member.ID] = normalized
	}
	return normalized, changed
}

// MergeMembers merges a list of member records, returning counts of new/updated nodes.
func (s *Store) MergeMembers(members []Member, now time.Time) (added, updated int) {
	if now.IsZero() {
		now = time.Now()
	}
	for _, m := range members {
		if m.ID == "" {
			continue
		}
		m.LastSeen = now
		_, existed := s.Member(m.ID)
		_, changed := s.Upsert(m, now)
		if changed {
			if existed {
				updated++
			} else {
				added++
			}
		}
	}
	return added, updated
}

// RecordHeartbeat refreshes lastSeen for a member, returning false if unknown.
func (s *Store) RecordHeartbeat(nodeID string, ts time.Time) bool {
	if ts.IsZero() {
		ts = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	member, ok := s.members[nodeID]
	if !ok {
		return false
	}
	member.LastSeen = ts
	s.members[nodeID] = member
	return true
}

// SetLocalApps replaces local app registrations in the store.
func (s *Store) SetLocalApps(apps []registry.AppPresence, now time.Time) {
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, app := range s.apps {
		if app.NodeID == s.self.ID {
			delete(s.apps, id)
		}
	}
	for _, app := range apps {
		if app.AppID == "" {
			continue
		}
		if app.ConnectedAt.IsZero() {
			app.ConnectedAt = now
		}
		app.Metadata = cloneMetadata(app.Metadata)
		s.apps[app.AppID] = app
	}
}

// MergeApps updates remote app registrations. Returns count of changed records.
func (s *Store) MergeApps(apps []registry.AppPresence, now time.Time) int {
	if now.IsZero() {
		now = time.Now()
	}
	changes := 0

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, app := range apps {
		if app.AppID == "" || app.NodeID == "" {
			continue
		}
		if app.ConnectedAt.IsZero() {
			app.ConnectedAt = now
		}
		app.Metadata = cloneMetadata(app.Metadata)
		existing, ok := s.apps[app.AppID]
		if !ok || existing.NodeID != app.NodeID || existing.SessionID != app.SessionID {
			changes++
		}
		s.apps[app.AppID] = app
	}
	return changes
}

// Apps returns all tracked app registrations.
func (s *Store) Apps() []registry.AppPresence {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]registry.AppPresence, 0, len(s.apps))
	for _, app := range s.apps {
		app.Metadata = cloneMetadata(app.Metadata)
		out = append(out, app)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AppID < out[j].AppID })
	return out
}

// ResolveApp returns the stored presence for a target app.
func (s *Store) ResolveApp(appID string) (registry.AppPresence, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	app, ok := s.apps[appID]
	if !ok {
		return registry.AppPresence{}, false
	}
	app.Metadata = cloneMetadata(app.Metadata)
	return app, true
}

// RemoveAppsForNode evicts app entries hosted on a given node.
func (s *Store) RemoveAppsForNode(nodeID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, app := range s.apps {
		if app.NodeID == nodeID {
			delete(s.apps, id)
			removed++
		}
	}
	return removed
}

// EvictStale removes members that have not heartbeated since the cutoff time.
func (s *Store) EvictStale(cutoff time.Time) []Member {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed []Member
	for id, member := range s.members {
		if id == s.self.ID {
			continue
		}
		if member.LastSeen.Before(cutoff) {
			delete(s.members, id)
			removed = append(removed, cloneMember(member))
			for appID, app := range s.apps {
				if app.NodeID == id {
					delete(s.apps, appID)
				}
			}
		}
	}
	return removed
}

func cloneMember(in Member) Member {
	cp := in
	cp.Metadata = cloneMetadata(in.Metadata)
	cp.IdentityKey = append([]byte(nil), in.IdentityKey...)
	return cp
}

func memberEqual(a, b Member) bool {
	if a.ID != b.ID || a.Endpoint != b.Endpoint || a.Wallet != b.Wallet || !a.LastSeen.Equal(b.LastSeen) {
		return false
	}
	if len(a.IdentityKey) != len(b.IdentityKey) {
		return false
	}
	for i := range a.IdentityKey {
		if a.IdentityKey[i] != b.IdentityKey[i] {
			return false
		}
	}
	if len(a.Metadata) != len(b.Metadata) {
		return false
	}
	for k, v := range a.Metadata {
		if b.Metadata[k] != v {
			return false
		}
	}
	return true
}

func cloneMetadata(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
