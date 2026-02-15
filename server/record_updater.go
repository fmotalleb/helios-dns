// Package server coordinates DNS serving and background record updates.
package server

import (
	"context"
	"iter"
	"net"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/fmotalleb/go-tools/log"

	"github.com/fmotalleb/mithra/vm"

	"github.com/fmotalleb/helios-dns/config"
)

func recordUpdater(ctx context.Context, cfg config.Config, h *dnsHandler) error {
	logger := log.Of(ctx)

	logger.Info("record updater started",
		zap.Int("domains_count", len(cfg.Domains)),
	)

	group, groupCtx := errgroup.WithContext(ctx)
	for _, v := range cfg.Domains {
		group.Go(func() error {
			return processDomain(groupCtx, v, h, logger)
		})
	}

	if err := group.Wait(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger.Info("record updater finished")
	return nil
}

func processDomain(ctx context.Context, cfg *config.ScanConfig, h *dnsHandler, logger *zap.Logger) error {
	domainLogger := logger.With(
		zap.String("domain", cfg.Domain),
		zap.String("sni", cfg.SNI),
	)
	domainLogger.Info("processing domain",
		zap.Int("limit", cfg.Limit),
	)

	vmRuntime, err := cfg.BuildVM()
	if err != nil {
		domainLogger.Error("failed to build VM", zap.Error(err))
		return err
	}

	limit := normalizeLimit(cfg.Limit)

	sample, err := cfg.ReadCIDRsSamples()
	if err != nil {
		domainLogger.Error("failed to read CIDR samples", zap.Error(err))
		return err
	}

	domainLogger.Debug("CIDR samples loaded")

	okIPs, err := collectIPs(ctx, vmRuntime, sample, domainLogger, limit)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}

	h.UpdateRecords(cfg.Domain, okIPs)

	domainLogger.Info("records updated",
		zap.Int("accepted_ips", len(okIPs)),
	)
	return nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 1
	}
	return limit
}

func collectIPs(
	ctx context.Context,
	vmRuntime *vm.VM,
	samples []iter.Seq[net.IP],
	logger *zap.Logger,
	limit int,
) ([]net.IP, error) {
	okIPs := make([]net.IP, 0, limit)

	domainCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var okMu sync.Mutex
	var wg sync.WaitGroup
	for _, cidrIter := range samples {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range cidrIter {
				select {
				case <-domainCtx.Done():
					return
				default:
				}

				logger.Debug("testing IP",
					zap.String("ip", ip.String()),
				)

				res := vmRuntime.ExecuteIP(domainCtx, ip)
				if !res.Success {
					logger.Debug("IP rejected",
						zap.String("ip", ip.String()),
					)
					continue
				}

				ipCopy := make(net.IP, len(ip))
				copy(ipCopy, ip)

				okMu.Lock()
				if len(okIPs) < limit {
					okIPs = append(okIPs, ipCopy)
					logger.Debug("IP accepted",
						zap.String("ip", ipCopy.String()),
						zap.Int("accepted_count", len(okIPs)),
					)
					if len(okIPs) == limit {
						cancel()
					}
				}
				okMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return okIPs, nil
	}
	return okIPs, nil
}
