package mesh

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	knownNodes       prometheus.Gauge
	joinSuccess      prometheus.Counter
	joinFailure      prometheus.Counter
	gossipHeartbeats prometheus.Counter
	appSyncTotal     prometheus.Counter
	suspectedPeers   prometheus.Gauge
	evictedPeers     prometheus.Counter
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &Metrics{
		knownNodes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hermes_mesh_nodes",
			Help: "Current number of known mesh nodes (including self).",
		}),
		joinSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_mesh_join_success_total",
			Help: "Successful join exchanges with peers.",
		}),
		joinFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_mesh_join_failure_total",
			Help: "Failed join attempts with peers.",
		}),
		gossipHeartbeats: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_mesh_heartbeats_total",
			Help: "Heartbeats received via gossip streams.",
		}),
		appSyncTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_mesh_appsync_total",
			Help: "App presence sync frames processed.",
		}),
		suspectedPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hermes_mesh_suspected_peers",
			Help: "Peers currently marked suspected by SWIM-like watchdog.",
		}),
		evictedPeers: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hermes_mesh_evicted_peers_total",
			Help: "Peers evicted after missed heartbeats.",
		}),
	}

	reg.MustRegister(
		m.knownNodes,
		m.joinSuccess,
		m.joinFailure,
		m.gossipHeartbeats,
		m.appSyncTotal,
		m.suspectedPeers,
		m.evictedPeers,
	)
	return m
}

func (m *Metrics) SetKnownNodes(n int) {
	if m == nil {
		return
	}
	m.knownNodes.Set(float64(n))
}

func (m *Metrics) RecordJoinSuccess() {
	if m == nil {
		return
	}
	m.joinSuccess.Inc()
}

func (m *Metrics) RecordJoinFailure() {
	if m == nil {
		return
	}
	m.joinFailure.Inc()
}

func (m *Metrics) RecordHeartbeat() {
	if m == nil {
		return
	}
	m.gossipHeartbeats.Inc()
}

func (m *Metrics) RecordAppSync() {
	if m == nil {
		return
	}
	m.appSyncTotal.Inc()
}

func (m *Metrics) SetSuspectedPeers(n int) {
	if m == nil {
		return
	}
	m.suspectedPeers.Set(float64(n))
}

func (m *Metrics) RecordEvictedPeer() {
	if m == nil {
		return
	}
	m.evictedPeers.Inc()
}
