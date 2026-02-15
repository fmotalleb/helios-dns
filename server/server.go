package server

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/fmotalleb/go-tools/log"
	"github.com/miekg/dns"

	"github.com/fmotalleb/helios-dns/config"
	dnsServer "github.com/fmotalleb/helios-dns/dns"
)

func Serve(ctx context.Context, cfg config.Config) error {
	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := log.Of(ctx)
	handler := &dnsHandler{
		logger: logger,
		rwMux:  new(sync.RWMutex),
		memory: make(map[string][]net.IP),
		ttl:    uint32(cfg.UpdateInterval.Seconds()),
	}
	errCh := make(chan error, 2)
	go func() {
		if err := dnsServer.Serve(localCtx, cfg.Listen, handler); err != nil {
			errCh <- err
		}
	}()
	timer := time.NewTimer(cfg.UpdateInterval)
	defer timer.Stop()
	go func() {
		for range timer.C {
			if err := recordUpdater(localCtx, cfg, handler); err != nil {
				errCh <- err
			}
		}
	}()
	// TODO: fail-fast scenario, handle errors
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

func recordUpdater(ctx context.Context, cfg config.Config, h *dnsHandler) error {
	logger := log.Of(ctx)

	logger.Info("record updater started",
		zap.Int("domains_count", len(cfg.Domains)),
	)

	group, groupCtx := errgroup.WithContext(ctx)
	for _, v := range cfg.Domains {
		v := v
		group.Go(func() error {
			domain := v.Domain
			sni := v.SNI
			logger.Info("processing domain",
				zap.String("domain", domain),
				zap.String("sni", sni),
				zap.Int("limit", v.Limit),
			)

			vm, err := v.BuildVM()
			if err != nil {
				logger.Error("failed to build VM",
					zap.String("domain", domain),
					zap.Error(err),
				)
				return err
			}

			limit := v.Limit
			if limit <= 0 {
				limit = 1
			}
			okIPs := make([]net.IP, 0, limit)

			sample, err := v.ReadCIDRsSamples()
			if err != nil {
				logger.Error("failed to read CIDR samples",
					zap.String("domain", domain),
					zap.Error(err),
				)
				return err
			}

			logger.Debug("CIDR samples loaded",
				zap.String("domain", domain),
			)

			domainCtx, cancel := context.WithCancel(groupCtx)
			defer cancel()

			jobs := make(chan net.IP)
			var wg sync.WaitGroup
			var okMu sync.Mutex

			worker := func() {
				defer wg.Done()
				for {
					select {
					case <-domainCtx.Done():
						return
					case ip, ok := <-jobs:
						if !ok {
							return
						}
						logger.Debug("testing IP",
							zap.String("domain", domain),
							zap.String("ip", ip.String()),
						)

						res := vm.ExecuteIP(domainCtx, ip)

						if res.Success {
							ipCopy := make(net.IP, len(ip))
							copy(ipCopy, ip)
							okMu.Lock()
							if len(okIPs) < limit {
								okIPs = append(okIPs, ipCopy)
								logger.Debug("IP accepted",
									zap.String("domain", domain),
									zap.String("ip", ipCopy.String()),
									zap.Int("accepted_count", len(okIPs)),
								)
								if len(okIPs) == limit {
									cancel()
								}
							}
							okMu.Unlock()
						} else {
							logger.Debug("IP rejected",
								zap.String("domain", domain),
								zap.String("ip", ip.String()),
							)
						}
					}
				}
			}

			wg.Add(limit)
			for i := 0; i < limit; i++ {
				go worker()
			}

		feed:
			for _, iter := range sample {
				for ip := range iter {
					select {
					case <-domainCtx.Done():
						break feed
					case jobs <- ip:
					}
				}
			}
			close(jobs)
			wg.Wait()

			if groupCtx.Err() != nil {
				return nil
			}

			h.UpdateRecords(domain, okIPs)

			logger.Info("records updated",
				zap.String("domain", domain),
				zap.Int("accepted_ips", len(okIPs)),
			)
			return nil
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

type dnsHandler struct {
	logger *zap.Logger
	rwMux  *sync.RWMutex
	memory map[string][]net.IP

	ttl uint32
}

func (d *dnsHandler) UpdateRecords(key string, records []net.IP) {
	d.rwMux.Lock()
	defer d.rwMux.Unlock()
	d.memory[key] = records
}

// ServeDNS implements [dns.Handler].
func (d *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	if len(r.Question) == 0 {
		if err := w.WriteMsg(msg); err != nil {
			d.logger.Info("failed to write answer to empty question", zap.Error(err))
		}
		return
	}
	q := r.Question[0]
	logger := d.logger.WithLazy(
		zap.String("name", q.Name),
		zap.Uint16("class", q.Qclass),
		zap.Uint16("type", q.Qtype),
		zap.String("from", w.RemoteAddr().String()),
	)
	logger.Debug("handling dns request")
	if q.Qtype != dns.TypeA {
		if err := w.WriteMsg(msg); err != nil {
			d.logger.Info("failed to write answer to non A record request", zap.Error(err))
		}
		return
	}

	d.rwMux.RLock()
	defer d.rwMux.RUnlock()
	res, ok := d.memory[q.Name]
	if !ok {
		if err := w.WriteMsg(msg); err != nil {
			d.logger.Info("failed to write empty answer to unknown request", zap.Error(err))
		}
		return
	}
	for _, addr := range res {
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				// In seconds
				Ttl: d.ttl,
			},
			A: addr,
		}
		msg.Answer = append(msg.Answer, rr)
	}
	if err := w.WriteMsg(msg); err != nil {
		logger.Warn("failed to write answer", zap.Error(err))
	}
}
