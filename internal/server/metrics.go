package server

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type routerMetrics struct {
	activeSessions prometheus.Gauge
	activeChats    prometheus.Gauge
	sessionTotal   prometheus.Counter
	frameErrors    *prometheus.CounterVec
	frameLatency   *prometheus.HistogramVec
	chatExpired    prometheus.Counter
}

func newRouterMetrics(reg prometheus.Registerer) *routerMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &routerMetrics{
		activeSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hermes_sessions_active",
			Help: "Current number of active app sessions.",
		}),
		activeChats: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hermes_chats_active",
			Help: "Current number of active chats on the node.",
		}),
		sessionTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_sessions_total",
			Help: "Total number of sessions handled since start.",
		}),
		frameErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hermes_router_errors_total",
			Help: "AppRouter frame validation or routing errors.",
		}, []string{"code"}),
		frameLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hermes_router_latency_seconds",
			Help:    "Latency for handling AppRouter frames.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		}, []string{"op"}),
		chatExpired: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_chats_expired_total",
			Help: "Chats expired by housekeeping.",
		}),
	}

	reg.MustRegister(
		m.activeSessions,
		m.activeChats,
		m.sessionTotal,
		m.frameErrors,
		m.frameLatency,
		m.chatExpired,
	)
	return m
}

func (m *routerMetrics) incSession() {
	if m == nil {
		return
	}
	m.activeSessions.Inc()
	m.sessionTotal.Inc()
}

func (m *routerMetrics) decSession() {
	if m == nil {
		return
	}
	m.activeSessions.Dec()
}

func (m *routerMetrics) incChat() {
	if m == nil {
		return
	}
	m.activeChats.Inc()
}

func (m *routerMetrics) decChat() {
	if m == nil {
		return
	}
	m.activeChats.Dec()
}

func (m *routerMetrics) recordError(code string) {
	if m == nil {
		return
	}
	m.frameErrors.WithLabelValues(code).Inc()
}

func (m *routerMetrics) observeLatency(op string, dur time.Duration) {
	if m == nil || op == "" {
		return
	}
	m.frameLatency.WithLabelValues(op).Observe(dur.Seconds())
}

func (m *routerMetrics) recordChatExpiry() {
	if m == nil {
		return
	}
	m.chatExpired.Inc()
}
