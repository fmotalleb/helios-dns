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
	dnsRequestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "helios_dns_requests_total",
			Help: "Total DNS requests received.",
		},
		[]string{"domain", "sni"},
	)
	dnsAnswerCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "helios_dns_answers_total",
			Help: "Total DNS answers returned.",
		},
		[]string{"domain", "sni"},
	)
	dnsAnswerRecordsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "helios_dns_answer_records_total",
			Help: "Total DNS answer records returned.",
		},
		[]string{"domain", "sni"},
	)
	scanAcceptedCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "helios_dns_scan_accepted_total",
			Help: "Total accepted IPs from scanner.",
		},
		[]string{"domain", "sni"},
	)
	scanRejectedCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "helios_dns_scan_rejected_total",
			Help: "Total rejected IPs from scanner.",
		},
		[]string{"domain", "sni"},
	)
)

func init() {
	prometheus.MustRegister(
		recordCountGauge,
		lastUpdateGauge,
		dnsRequestCounter,
		dnsAnswerCounter,
		dnsAnswerRecordsCounter,
		scanAcceptedCounter,
		scanRejectedCounter,
	)
}

func updateRecordMetrics(domain string, records []net.IP, updatedAt time.Time) {
	recordCountGauge.WithLabelValues(domain).Set(float64(len(records)))
	lastUpdateGauge.WithLabelValues(domain).Set(float64(updatedAt.Unix()))
}

func recordDNSRequest(domain string, sni string) {
	dnsRequestCounter.WithLabelValues(domain, sni).Inc()
}

func recordDNSAnswer(domain string, sni string, recordCount int) {
	dnsAnswerCounter.WithLabelValues(domain, sni).Inc()
	dnsAnswerRecordsCounter.WithLabelValues(domain, sni).Add(float64(recordCount))
}

func recordScanResult(domain string, sni string, accepted bool) {
	if accepted {
		scanAcceptedCounter.WithLabelValues(domain, sni).Inc()
		return
	}
	scanRejectedCounter.WithLabelValues(domain, sni).Inc()
}
