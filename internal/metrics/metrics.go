package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	Connects   *prometheus.CounterVec
	EdgeTotal  *prometheus.CounterVec
	TxDuration *prometheus.HistogramVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Connects: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netagent_connect_total",
				Help: "Connect events (TCP/UDP) by process, protocol, destination port and destination IP",
			},
			[]string{"process", "proto", "dport", "dst_ip"},
		),
		EdgeTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netagent_edge_total",
				Help: "Edge events by process, protocol, destination IP and port",
			},
			[]string{"process", "proto", "dport", "dst_ip"},
		),
		TxDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "netagent_tx_duration_seconds",
				Help:    "Observed send->recv durations by process, protocol, destination port and destination IP",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
			},
			[]string{"process", "proto", "dport", "dst_ip"},
		),
	}
	reg.MustRegister(m.Connects)
	reg.MustRegister(m.EdgeTotal)
	reg.MustRegister(m.TxDuration)
	return m
}
