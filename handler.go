package post

import (
	"crypto/tls"
	"net"
	"net/url"
	"time"
)

type (
	HandlerOption func(opts *HandlerOptions)

	Handler interface {
		Init(options ...HandlerOption)
		Handle(net.Conn)
	}

	HandlerOptions struct {
		Addr          string
		Chain         *Chain
		Users         []*url.Userinfo
		Authenticator Authenticator
		TLSConfig     *tls.Config
		Whitelist     *Permissions
		Blacklist     *Permissions
		Retries       int
		Timeout       time.Duration
		Resolver      Resolver
		Hosts         *Hosts
		ProbeResist   string
		KnockingHost  string
		Node          Node
		ProxyAgent    string
		HTTPTunnel    bool
	}
)

func AddrHandlerOption(addr string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Addr = addr
	}
}
