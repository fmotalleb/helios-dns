package server

import (
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	recordCountGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "helios_dns_records_total",
			Help: "Number of accepted IPs per domain.",
		},
		[]string{"domain"},
	)
	lastUpdateGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "helios_dns_last_update_timestamp",
			Help: "Unix timestamp of the last update per domain.",
		},
		[]string{"domain"},
	)
)

func init() {
	prometheus.MustRegister(recordCountGauge, lastUpdateGauge)
}

func updateRecordMetrics(domain string, records []net.IP, updatedAt time.Time) {
	recordCountGauge.WithLabelValues(domain).Set(float64(len(records)))
	lastUpdateGauge.WithLabelValues(domain).Set(float64(updatedAt.Unix()))
}
