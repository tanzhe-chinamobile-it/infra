package tcpfirewall

import (
	"context"
	"fmt"
	"net"
	"sync"

	xproxy "golang.org/x/net/proxy"
)

type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func newSOCKS5DialContext(proxyAddr string) (DialContextFunc, error) {
	dialer, err := xproxy.SOCKS5("tcp", proxyAddr, nil, xproxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer for %q: %w", proxyAddr, err)
	}

	ctxDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer does not support DialContext")
	}

	return ctxDialer.DialContext, nil
}

type socks5DialerCache struct {
	mu      sync.RWMutex
	dialers map[string]DialContextFunc
}

func (c *socks5DialerCache) Get(addr string) (DialContextFunc, error) {
	c.mu.RLock()
	if fn, ok := c.dialers[addr]; ok {
		c.mu.RUnlock()

		return fn, nil
	}
	c.mu.RUnlock()

	fn, err := newSOCKS5DialContext(addr)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.dialers == nil {
		c.dialers = make(map[string]DialContextFunc)
	}

	if existing, ok := c.dialers[addr]; ok {
		c.mu.Unlock()

		return existing, nil
	}

	c.dialers[addr] = fn
	c.mu.Unlock()

	return fn, nil
}

type socks5CtxKey struct{}

func withSOCKS5DialContext(ctx context.Context, fn DialContextFunc) context.Context {
	return context.WithValue(ctx, socks5CtxKey{}, fn)
}

func socks5DialContextFromCtx(ctx context.Context) DialContextFunc {
	fn, _ := ctx.Value(socks5CtxKey{}).(DialContextFunc)

	return fn
}
