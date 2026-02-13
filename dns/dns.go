package dns

import (
	"context"
	"net"

	"github.com/fmotalleb/go-tools/log"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func Serve(ctx context.Context, listenAddr string, h dns.Handler) error {
	logger := log.Of(ctx)
	listener := new(net.ListenConfig)
	l, err := listener.ListenPacket(ctx, "udp", listenAddr)
	if err != nil {
		logger.Error("failed to start server", zap.Error(err))
		return err
	}
	logger.Info("dns server started", zap.String("listen", listenAddr))
	if serverErr := dns.ActivateAndServe(nil, l, h); serverErr != nil {
		select {
		case <-ctx.Done():
			return nil
		default:
			return serverErr
		}
	}
	return nil
}
