package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAppliesDefaultsAndValidates(t *testing.T) {
	t.Parallel()

	cfgPath := writeTestConfig(t, `
listen: 127.0.0.1:5657
interval: 1m
domains:
  - domain: "edge.example.com."
    sni: "origin.example.com"
`)

	args := defaultArgs()
	argsMap := args["args"].(map[string]any)
	argsMap["path"] = "/healthz"

	var cfg Config
	err := Parse(context.Background(), &cfg, cfgPath, args)
	if err != nil {
		t.Fatalf("Parse() returned error: %v", err)
	}

	if got := cfg.Domains[0].Path; got != "/healthz" {
		t.Fatalf("domain path = %q, want %q", got, "/healthz")
	}
	if len(cfg.Domains[0].CIDRs) != 1 || cfg.Domains[0].CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("domain cidr fallback not applied: got %#v", cfg.Domains[0].CIDRs)
	}
}

func TestParseRejectsInvalidPath(t *testing.T) {
	t.Parallel()

	cfgPath := writeTestConfig(t, `
listen: 127.0.0.1:5657
interval: 1m
domains:
  - domain: "edge.example.com."
    sni: "origin.example.com"
    cidr: ["198.51.100.0/24"]
    timeout: 1000000
    port: 443
    path: "health"
    status_code: 200
`)

	var cfg Config
	err := Parse(context.Background(), &cfg, cfgPath, defaultArgs())
	if err == nil {
		t.Fatal("Parse() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "path: must start with '/'") {
		t.Fatalf("Parse() error = %q, want path validation error", err)
	}
}

func TestParseRejectsInvalidSamplingBounds(t *testing.T) {
	t.Parallel()

	cfgPath := writeTestConfig(t, `
listen: 127.0.0.1:5657
interval: 1m
domains:
  - domain: "edge.example.com."
    sni: "origin.example.com"
    cidr: ["198.51.100.0/24"]
    timeout: 1000000
    port: 443
    path: "/healthz"
    sample_min: 9
    sample_max: 2
`)

	var cfg Config
	err := Parse(context.Background(), &cfg, cfgPath, defaultArgs())
	if err == nil {
		t.Fatal("Parse() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sample_min: must be less than or equal to sample_max") {
		t.Fatalf("Parse() error = %q, want sample bound validation error", err)
	}
}

func TestParseRejectsMissingDomains(t *testing.T) {
	t.Parallel()

	cfgPath := writeTestConfig(t, `
listen: 127.0.0.1:5657
interval: 1m
`)

	var cfg Config
	err := Parse(context.Background(), &cfg, cfgPath, defaultArgs())
	if err == nil {
		t.Fatal("Parse() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "domains: must contain at least one item") {
		t.Fatalf("Parse() error = %q, want domains validation error", err)
	}
}

func writeTestConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}

func defaultArgs() map[string]any {
	return map[string]any{
		"args": map[string]any{
			"listen":        "127.0.0.1:5353",
			"interval":      (10 * time.Minute).Nanoseconds(),
			"cidrs":         []string{"198.51.100.0/24"},
			"sni":           "origin.example.com",
			"path":          "/",
			"timeout":       (200 * time.Millisecond).Nanoseconds(),
			"port":          443,
			"status_code":   200,
			"sample_min":    0,
			"sample_max":    8,
			"sample_chance": 0.05,
			"http_only":     false,
		},
	}
}
