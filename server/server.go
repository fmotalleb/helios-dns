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

// Serve starts the DNS server and periodic record updater loop.
func Serve(ctx context.Context, cfg config.Config) error {
	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := log.Of(ctx)
	handler := &dnsHandler{
		logger:      logger,
		rwMux:       new(sync.RWMutex),
		memory:      make(map[string][]net.IP),
		updatedAt:   make(map[string]time.Time),
		sniByDomain: make(map[string]string),
		ttl:         uint32(cfg.UpdateInterval.Seconds()),
	}
	for _, domainCfg := range cfg.Domains {
		handler.sniByDomain[domainCfg.Domain] = domainCfg.SNI
	}
	group, groupCtx := errgroup.WithContext(localCtx)

	group.Go(func() error {
		if err := dnsServer.Serve(groupCtx, cfg.Listen, handler); err != nil {
			return err
		}
		return nil
	})
	if cfg.HTTPListen != "" {
		group.Go(func() error {
			if err := serveHTTP(groupCtx, cfg.HTTPListen, cfg, handler); err != nil {
				return err
			}
			return nil
		})
	}
	timer := time.NewTimer(cfg.UpdateInterval)
	defer timer.Stop()
	group.Go(func() error {
		if err := recordUpdater(groupCtx, cfg, handler); err != nil {
			return err
		}
		for range timer.C {
			if err := recordUpdater(groupCtx, cfg, handler); err != nil {
				return err
			}
			timer.Reset(cfg.UpdateInterval)
		}
		return nil
	})

	return group.Wait()
}

type dnsHandler struct {
	logger      *zap.Logger
	rwMux       *sync.RWMutex
	memory      map[string][]net.IP
	updatedAt   map[string]time.Time
	sniByDomain map[string]string

	ttl uint32
}

func (d *dnsHandler) UpdateRecords(key string, records []net.IP) {
	now := time.Now()
	d.rwMux.Lock()
	defer d.rwMux.Unlock()
	d.memory[key] = records
	d.updatedAt[key] = now
	updateRecordMetrics(key, records, now)
}

type recordSnapshot struct {
	IPs       []net.IP
	UpdatedAt time.Time
}

func (d *dnsHandler) Snapshot() map[string]recordSnapshot {
	d.rwMux.RLock()
	defer d.rwMux.RUnlock()
	result := make(map[string]recordSnapshot, len(d.memory))
	for key, records := range d.memory {
		copyRecords := make([]net.IP, len(records))
		for i, ip := range records {
			ipCopy := make(net.IP, len(ip))
			copy(ipCopy, ip)
			copyRecords[i] = ipCopy
		}
		result[key] = recordSnapshot{
			IPs:       copyRecords,
			UpdatedAt: d.updatedAt[key],
		}
	}
	return result
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
	sni := d.sniByDomain[q.Name]
	recordDNSRequest(q.Name, sni)
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
	recordDNSAnswer(q.Name, sni, len(res))
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
