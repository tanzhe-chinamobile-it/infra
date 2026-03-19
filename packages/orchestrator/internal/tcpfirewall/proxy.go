package tcpfirewall

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/inetaf/tcpproxy"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox"
	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/connlimit"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

var _ sandbox.MapSubscriber = (*Proxy)(nil)

type Proxy struct {
	logger       logger.Logger
	sandboxes    *sandbox.Map
	metrics      *Metrics
	limiter      *connlimit.ConnectionLimiter
	featureFlags *featureflags.Client

	// Separate ports for different traffic types to avoid protocol detection blocking
	// on server-first protocols like SSH.
	httpPort  uint16 // For port 80 traffic - HTTP Host header inspection
	tlsPort   uint16 // For port 443 traffic - TLS SNI inspection
	otherPort uint16 // For all other ports - CIDR-only, no protocol inspection

	socks5Dialers socks5DialerCache

	proxy *tcpproxy.Proxy
}

func New(logger logger.Logger, networkConfig network.Config, sandboxes *sandbox.Map, meterProvider metric.MeterProvider, featureFlags *featureflags.Client) *Proxy {
	p := &Proxy{
		httpPort:     networkConfig.SandboxTCPFirewallHTTPPort,
		tlsPort:      networkConfig.SandboxTCPFirewallTLSPort,
		otherPort:    networkConfig.SandboxTCPFirewallOtherPort,
		logger:       logger,
		sandboxes:    sandboxes,
		metrics:      NewMetrics(meterProvider),
		limiter:      connlimit.NewConnectionLimiter(),
		featureFlags: featureFlags,
	}

	sandboxes.Subscribe(p)

	return p
}

func (p *Proxy) OnInsert(_ *sandbox.Sandbox) {}

func (p *Proxy) OnRemove(sandboxID string) {
	p.limiter.Remove(sandboxID)
}

func (p *Proxy) Start(ctx context.Context) error {
	p.proxy = &tcpproxy.Proxy{}

	p.proxy.ListenFunc = func(network, laddr string) (net.Listener, error) {
		lc := net.ListenConfig{}
		ln, err := lc.Listen(ctx, network, laddr)
		if err != nil {
			return nil, err
		}

		return &resilientListener{
			Listener: ln,
			ctx:      ctx,
			logger:   p.logger,
		}, nil
	}

	// Three separate addresses for different traffic types.
	// iptables redirects traffic based on original destination port:
	// - dport 80 → httpAddr (HTTP Host header inspection)
	// - dport 443 → tlsAddr (TLS SNI inspection)
	// - other dports → otherAddr (CIDR-only, no protocol inspection)
	httpAddr := fmt.Sprintf("0.0.0.0:%d", p.httpPort)
	tlsAddr := fmt.Sprintf("0.0.0.0:%d", p.tlsPort)
	otherAddr := fmt.Sprintf("0.0.0.0:%d", p.otherPort)

	// HTTP listener (port 80 traffic): inspect Host header for domain allowlist
	p.proxy.AddHTTPHostMatchRoute(httpAddr, func(_ context.Context, _ string) bool { return true }, p.newConnectionHandler(ctx, domainHandler, ProtocolHTTP))
	p.proxy.AddRoute(httpAddr, p.newConnectionHandler(ctx, cidrOnlyHandler, ProtocolHTTP))

	// TLS listener (port 443 traffic): inspect SNI for domain allowlist
	p.proxy.AddSNIMatchRoute(tlsAddr, func(_ context.Context, _ string) bool { return true }, p.newConnectionHandler(ctx, domainHandler, ProtocolTLS))
	p.proxy.AddRoute(tlsAddr, p.newConnectionHandler(ctx, cidrOnlyHandler, ProtocolTLS))

	// Other listener (all other ports): CIDR-only check, no protocol inspection
	// This prevents blocking on server-first protocols like SSH
	p.proxy.AddRoute(otherAddr, p.newConnectionHandler(ctx, cidrOnlyHandler, ProtocolOther))

	p.logger.Info(ctx, "TCP firewall proxy started",
		zap.Uint16("http_port", p.httpPort),
		zap.Uint16("tls_port", p.tlsPort),
		zap.Uint16("other_port", p.otherPort))

	go func() {
		<-ctx.Done()
		p.proxy.Close()
	}()

	err := p.proxy.Run()
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		// This is expected when the proxy is closed.
		return nil
	}

	return err
}

func (p *Proxy) Close(_ context.Context) error {
	if p.proxy != nil {
		return p.proxy.Close()
	}

	return nil
}

// handlerFunc is the signature for connection handlers.
type handlerFunc func(ctx context.Context, conn net.Conn, dstIP net.IP, dstPort int, sbx *sandbox.Sandbox, logger logger.Logger, metrics *Metrics, protocol Protocol)

var _ tcpproxy.Target = (*connectionHandler)(nil)

// connectionHandler adapts a handler function to tcpproxy.Target interface.
type connectionHandler struct {
	ctx context.Context //nolint:containedctx // base context for request tracing

	handler       handlerFunc
	protocol      Protocol
	metrics       *Metrics
	limiter       *connlimit.ConnectionLimiter
	logger        logger.Logger
	sandboxes     *sandbox.Map
	featureFlags  *featureflags.Client
	socks5Dialers *socks5DialerCache // stable egress IP proxy cache
}

func (p *Proxy) newConnectionHandler(ctx context.Context, handler handlerFunc, protocol Protocol) *connectionHandler {
	return &connectionHandler{
		ctx:           ctx,
		handler:       handler,
		protocol:      protocol,
		metrics:       p.metrics,
		limiter:       p.limiter,
		logger:        p.logger,
		sandboxes:     p.sandboxes,
		featureFlags:  p.featureFlags,
		socks5Dialers: &p.socks5Dialers,
	}
}

func (t *connectionHandler) HandleConn(conn net.Conn) {
	// Request tracing context.
	ctx := t.ctx

	// Get the underlying connection for sandbox lookup and original dst.
	// tcpproxy may wrap in *tcpproxy.Conn for peeked bytes.
	rawConn := tcpproxy.UnderlyingConn(conn)

	// Look up sandbox by source address
	sourceAddr := rawConn.RemoteAddr().String()
	sbx, err := t.sandboxes.GetByHostPort(sourceAddr)
	if err != nil {
		sourceIP, _, _ := net.SplitHostPort(sourceAddr)
		t.logger.Error(ctx, "failed to find sandbox for connection",
			logger.WithSandboxIP(sourceIP),
			zap.Error(err))
		t.metrics.RecordError(ctx, ErrorTypeSandboxLookup, t.protocol)
		conn.Close()

		return
	}

	sandboxID := sbx.Runtime.SandboxID
	sbxLogger := t.logger.With(logger.WithSandboxID(sandboxID))

	// Check per-sandbox connection limit
	maxLimit := t.featureFlags.IntFlag(ctx, featureflags.TCPFirewallMaxConnectionsPerSandbox)
	count, acquired := t.limiter.TryAcquire(sandboxID, maxLimit)
	if !acquired {
		t.metrics.RecordError(ctx, ErrorTypeLimitExceeded, t.protocol)
		conn.Close()

		return
	}

	// Get original destination (before iptables redirect)
	ip, port, err := getOriginalDst(rawConn)
	if err != nil {
		sbxLogger.Error(ctx, "failed to get original destination", zap.Error(err))
		t.metrics.RecordError(ctx, ErrorTypeOrigDst, t.protocol)
		t.limiter.Release(sandboxID)
		conn.Close()

		return
	}

	t.metrics.RecordConnectionsPerSandbox(ctx, count)
	t.metrics.RecordConnection(ctx, t.protocol)

	proxyAddr := t.featureFlags.StringFlag(ctx, featureflags.SandboxEgressProxy,
		featureflags.TeamContext(sbx.Runtime.TeamID))
	if proxyAddr != "" {
		dialCtx, dialErr := t.socks5Dialers.Get(proxyAddr)
		if dialErr != nil {
			sbxLogger.Error(ctx, "failed to create SOCKS5 dialer for egress proxy",
				zap.String("proxy_addr", proxyAddr),
				zap.Error(dialErr))
		} else {
			ctx = withSOCKS5DialContext(ctx, dialCtx)
		}
	}

	// Wrap the handler to release the connection slot when done
	wrappedHandler := func(ctx context.Context, conn net.Conn, dstIP net.IP, dstPort int, sbx *sandbox.Sandbox, l logger.Logger, metrics *Metrics, protocol Protocol) {
		defer t.limiter.Release(sandboxID)
		t.handler(ctx, conn, dstIP, dstPort, sbx, l, metrics, protocol)
	}

	wrappedHandler(ctx, conn, ip, port, sbx, sbxLogger, t.metrics, t.protocol)
}
