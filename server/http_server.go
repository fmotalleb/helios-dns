package server

import (
	"context"
	"embed"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/fmotalleb/go-tools/log"

	"github.com/fmotalleb/helios-dns/config"
)

//go:embed static/*
var staticFS embed.FS

type statusResponse struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Domains     []domainStatus `json:"domains"`
}

type domainStatus struct {
	Domain     string     `json:"domain"`
	IPs        []string   `json:"ips"`
	LastUpdate string     `json:"last_update"`
	Config     configView `json:"config"`
}

type configView struct {
	Domain        string   `json:"domain"`
	CIDRs         []string `json:"cidr"`
	SNI           string   `json:"sni"`
	Timeout       string   `json:"timeout"`
	Port          int      `json:"port"`
	Path          string   `json:"path"`
	StatusCode    int      `json:"status_code"`
	SamplesMin    int      `json:"sample_min"`
	SamplesMax    int      `json:"sample_max"`
	SamplesChance float64  `json:"sample_chance"`
	HTTPOnly      bool     `json:"http_only"`
	ResultLimit   int      `json:"result_limit"`
}

func serveHTTP(ctx context.Context, addr string, cfg config.Config, handler *dnsHandler) error {
	const httpTimeout = 5 * time.Second

	logger := log.Of(ctx)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, staticFS, "static")
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		status := buildStatus(cfg, handler.Snapshot())
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(status)
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: httpTimeout,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("http server shutdown failed", zap.Error(err))
		}
	}()

	logger.Info("http server started", zap.String("listen", addr))
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func buildStatus(cfg config.Config, snapshot map[string]recordSnapshot) statusResponse {
	resp := statusResponse{
		GeneratedAt: time.Now(),
		Domains:     make([]domainStatus, 0, len(cfg.Domains)),
	}
	for _, domainCfg := range cfg.Domains {
		entry := domainStatus{
			Domain: domainCfg.Domain,
			IPs:    []string{},
			Config: configView{
				Domain:        domainCfg.Domain,
				CIDRs:         domainCfg.CIDRs,
				SNI:           domainCfg.SNI,
				Timeout:       (time.Duration(domainCfg.Timeout) * time.Nanosecond).String(),
				Port:          domainCfg.Port,
				Path:          domainCfg.Path,
				StatusCode:    domainCfg.StatusCode,
				SamplesMin:    domainCfg.SamplesMinimum,
				SamplesMax:    domainCfg.SamplesMaximum,
				SamplesChance: domainCfg.SamplesChance,
				HTTPOnly:      domainCfg.HTTPOnly,
				ResultLimit:   domainCfg.Limit,
			},
		}
		if snap, ok := snapshot[domainCfg.Domain]; ok {
			entry.LastUpdate = snap.UpdatedAt.Format(time.RFC3339)
			entry.IPs = ipsToStrings(snap.IPs)
		}
		resp.Domains = append(resp.Domains, entry)
	}
	return resp
}

func ipsToStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
