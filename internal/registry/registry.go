package registry

import (
	"errors"
	"sync"
	"time"
)

// ChatSession tracks metadata about an active chat.
type ChatSession struct {
	ChatID    string
	CreatedAt time.Time
	Metadata  map[string]string
}

// ChatRegistry keeps track of chat sessions hosted on the node.
type ChatRegistry interface {
	Register(chat ChatSession) error
	Get(chatID string) (ChatSession, bool)
	Delete(chatID string) bool
	List() []ChatSession
}

// InMemoryRegistry is a placeholder registry backed by a map.
type InMemoryRegistry struct {
	mu    sync.RWMutex
	chats map[string]ChatSession
	limit int
	nowFn func() time.Time
}

// NewInMemory creates a registry with an optional limit; zero means unbounded.
func NewInMemory(limit int) *InMemoryRegistry {
	return &InMemoryRegistry{
		chats: make(map[string]ChatSession),
		limit: limit,
		nowFn: time.Now,
	}
}

// Register stores a chat session if capacity allows.
func (r *InMemoryRegistry) Register(chat ChatSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if chat.ChatID == "" {
		return errors.New("chat id is required")
	}
	if _, exists := r.chats[chat.ChatID]; exists {
		return errors.New("chat already exists")
	}
	if r.limit > 0 && len(r.chats) >= r.limit {
		return errors.New("chat registry at capacity")
	}
	if chat.CreatedAt.IsZero() {
		chat.CreatedAt = r.nowFn()
	}
	r.chats[chat.ChatID] = chat
	return nil
}

// Get fetches a chat by ID.
func (r *InMemoryRegistry) Get(chatID string) (ChatSession, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	chat, ok := r.chats[chatID]
	return chat, ok
}

// Delete removes a chat by ID.
func (r *InMemoryRegistry) Delete(chatID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.chats[chatID]; !ok {
		return false
	}
	delete(r.chats, chatID)
	return true
}

// List enumerates all tracked chats.
func (r *InMemoryRegistry) List() []ChatSession {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ChatSession, 0, len(r.chats))
	for _, chat := range r.chats {
		out = append(out, chat)
	}
	return out
}
