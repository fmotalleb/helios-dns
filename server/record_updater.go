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

	maxWorkers := normalizeMaxWorkers(cfg.MaxWorkers)

	logger.Info("record updater started",
		zap.Int("domains_count", len(cfg.Domains)),
		zap.Int("max_workers", maxWorkers),
	)

	workerTokens := make(chan struct{}, maxWorkers)

	group, groupCtx := errgroup.WithContext(ctx)
	for _, v := range cfg.Domains {
		domainCfg := v
		group.Go(func() error {
			return processDomain(groupCtx, domainCfg, h, logger, workerTokens)
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

func processDomain(ctx context.Context, cfg *config.ScanConfig, h *dnsHandler, logger *zap.Logger, workerTokens chan struct{}) error {
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

	okIPs, err := collectIPs(ctx, vmRuntime, sample, domainLogger, limit, workerTokens, cfg.Domain, cfg.SNI)
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

func normalizeMaxWorkers(maxWorkers int) int {
	if maxWorkers <= 0 {
		return 1
	}
	return maxWorkers
}

func collectIPs(
	ctx context.Context,
	vmRuntime *vm.VM,
	samples []iter.Seq[net.IP],
	logger *zap.Logger,
	limit int,
	workerTokens chan struct{},
	domain string,
	sni string,
) ([]net.IP, error) {
	okIPs := make([]net.IP, 0, limit)
	seen := make(map[string]struct{}, limit)

	domainCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ipCh := make(chan net.IP)

	var producers sync.WaitGroup
	producers.Add(len(samples))
	for _, cidrIter := range samples {
		iter := cidrIter
		go func() {
			defer producers.Done()
			for ip := range iter {
				select {
				case <-domainCtx.Done():
					return
				case ipCh <- ip:
				}
			}
		}()
	}

	go func() {
		producers.Wait()
		close(ipCh)
	}()

	var okMu sync.Mutex
	var workers sync.WaitGroup
	workerCount := len(samples)
	if workerCount == 0 {
		return okIPs, nil
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-domainCtx.Done():
					return
				case ip, ok := <-ipCh:
					if !ok {
						return
					}

					select {
					case <-domainCtx.Done():
						return
					case workerTokens <- struct{}{}:
					}

					logger.Debug("testing IP",
						zap.String("ip", ip.String()),
					)

					res := vmRuntime.ExecuteIP(domainCtx, ip)

					<-workerTokens
					if !res.Success {
						recordScanResult(domain, sni, false)
						logger.Debug("IP rejected",
							zap.String("ip", ip.String()),
						)
						continue
					}
					recordScanResult(domain, sni, true)

					ipCopy := make(net.IP, len(ip))
					copy(ipCopy, ip)

					okMu.Lock()
					if len(okIPs) < limit {
						key := ipCopy.String()
						if _, exists := seen[key]; exists {
							okMu.Unlock()
							continue
						}
						seen[key] = struct{}{}
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
			}
		}()
	}
	workers.Wait()

	if ctx.Err() != nil {
		return okIPs, nil
	}
	return okIPs, nil
}
