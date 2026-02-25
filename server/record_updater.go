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
				if !sendIP(domainCtx, ipCh, ip) {
					return
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
			runWorker(domainCtx, ipCh, workerTokens, vmRuntime, logger, domain, sni, limit, &okMu, seen, &okIPs, cancel)
		}()
	}
	workers.Wait()

	if ctx.Err() != nil {
		return okIPs, nil
	}
	return okIPs, nil
}

func sendIP(ctx context.Context, out chan<- net.IP, ip net.IP) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- ip:
		return true
	}
}

func runWorker(
	ctx context.Context,
	ipCh <-chan net.IP,
	workerTokens chan struct{},
	vmRuntime *vm.VM,
	logger *zap.Logger,
	domain string,
	sni string,
	limit int,
	okMu *sync.Mutex,
	seen map[string]struct{},
	okIPs *[]net.IP,
	cancel context.CancelFunc,
) {
	for {
		ip, ok := recvIP(ctx, ipCh)
		if !ok {
			return
		}
		if !acquireToken(ctx, workerTokens) {
			return
		}
		success := runScan(ctx, vmRuntime, logger, ip)
		releaseToken(workerTokens)
		recordScanResult(domain, sni, success)
		if !success {
			continue
		}
		acceptIP(ip, limit, okMu, seen, okIPs, logger, cancel)
	}
}

func recvIP(ctx context.Context, ipCh <-chan net.IP) (net.IP, bool) {
	select {
	case <-ctx.Done():
		return nil, false
	case ip, ok := <-ipCh:
		if !ok {
			return nil, false
		}
		return ip, true
	}
}

func acquireToken(ctx context.Context, workerTokens chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case workerTokens <- struct{}{}:
		return true
	}
}

func releaseToken(workerTokens chan struct{}) {
	<-workerTokens
}

func runScan(ctx context.Context, vmRuntime *vm.VM, logger *zap.Logger, ip net.IP) bool {
	logger.Debug("testing IP",
		zap.String("ip", ip.String()),
	)
	res := vmRuntime.ExecuteIP(ctx, ip)
	if !res.Success {
		logger.Debug("IP rejected",
			zap.String("ip", ip.String()),
		)
	}
	return res.Success
}

func acceptIP(
	ip net.IP,
	limit int,
	okMu *sync.Mutex,
	seen map[string]struct{},
	okIPs *[]net.IP,
	logger *zap.Logger,
	cancel context.CancelFunc,
) {
	ipCopy := make(net.IP, len(ip))
	copy(ipCopy, ip)

	okMu.Lock()
	defer okMu.Unlock()
	if len(*okIPs) >= limit {
		return
	}
	key := ipCopy.String()
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*okIPs = append(*okIPs, ipCopy)
	logger.Debug("IP accepted",
		zap.String("ip", ipCopy.String()),
		zap.Int("accepted_count", len(*okIPs)),
	)
	if len(*okIPs) == limit {
		cancel()
	}
}
