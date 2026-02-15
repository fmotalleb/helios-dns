package config

import (
	"context"
	"fmt"

	"github.com/fmotalleb/go-tools/config"
	"github.com/fmotalleb/go-tools/decoder"
	"github.com/fmotalleb/go-tools/defaulter"
)

// Parse reads configuration from file and applies defaults from runtime args.
func Parse(ctx context.Context, dst *Config, path string, args map[string]any) error {
	if path != "" {
		cfg, err := config.ReadAndMergeConfig(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to read and merge configs: %w", err)
		}
		decoder, err := decoder.Build(dst)
		if err != nil {
			return fmt.Errorf("create decoder: %w", err)
		}

		if err := decoder.Decode(cfg); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
	}

	defaulter.ApplyDefaults(dst, args)
	for _, v := range dst.Domains {
		defaulter.ApplyDefaults(v, args)
		if len(v.CIDRs) == 0 {
			v.CIDRs = getCIDRs(args)
		}
	}
	return nil
}

func getCIDRs(args map[string]any) []string {
	m := args["args"].(map[string]any)
	return m["cidrs"].([]string)
}
