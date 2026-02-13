package server

import (
	"context"
	"net"
	"sync"

	"go.uber.org/zap"

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
	}
	go func() {
		dnsServer.Serve(localCtx, cfg.Listen, handler)
	}()
	go func() {
		recordUpdater(localCtx, cfg, handler)
	}()
	<-ctx.Done()
	return nil
}

func recordUpdater(ctx context.Context, cfg config.Config, h *dnsHandler) error {
	logger := log.Of(ctx)

	logger.Info("record updater started",
		zap.Int("domains_count", len(cfg.Domains)),
	)

	for _, v := range cfg.Domains {
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

		okIPs := make([]net.IP, 0, v.Limit)

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

	iters:
		for _, iter := range sample {
			for ip := range iter {
				logger.Debug("testing IP",
					zap.String("domain", domain),
					zap.String("ip", ip.String()),
				)

				res := vm.ExecuteIP(ctx, ip)

				if res.Success {
					ipCopy := make(net.IP, len(ip))
					copy(ipCopy, ip)
					okIPs = append(okIPs, ipCopy)

					logger.Debug("IP accepted",
						zap.String("domain", domain),
						zap.String("ip", ipCopy.String()),
						zap.Int("accepted_count", len(okIPs)),
					)

					if len(okIPs) == v.Limit {
						break iters
					}
					break
				} else {
					logger.Debug("IP rejected",
						zap.String("domain", domain),
						zap.String("ip", ip.String()),
					)
				}
			}
		}

		h.UpdateRecords(domain, okIPs)

		logger.Info("records updated",
			zap.String("domain", domain),
			zap.Int("accepted_ips", len(okIPs)),
		)
	}

	logger.Info("record updater finished")
	return nil
}

type dnsHandler struct {
	logger *zap.Logger
	rwMux  *sync.RWMutex
	memory map[string][]net.IP
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
				Ttl: 300,
			},
			A: addr,
		}
		msg.Answer = append(msg.Answer, rr)
	}
	if err := w.WriteMsg(msg); err != nil {
		logger.Warn("failed to write answer", zap.Error(err))
	}
}
