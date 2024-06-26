package post

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/go-gost/gosocks5"
)

type (
	DialOption      func(opts *DialOptions)
	HandshakeOption func(opts *HandshakeOptions)
	ConnectOption   func(opts *ConnectOptions)
	Connector       interface {
		Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error)
		ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error)
	}
	Transporter interface {
		Dial(addr string, options ...DialOption) (net.Conn, error)
		Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error)
		Multiplex() bool
	}
	Client struct {
		Connector
		Transporter
	}
	DialOptions struct {
		Timeout time.Duration
		Chain   *Chain
		Host    string
	}
	HandshakeOptions struct {
		Addr      string
		Host      string
		User      *url.Userinfo
		Timeout   time.Duration
		Interval  time.Duration
		Retry     int
		TLSConfig *tls.Config
	}
	ConnectOptions struct {
		Addr      string
		Timeout   time.Duration
		User      *url.Userinfo
		Selector  gosocks5.Selector
		UserAgent string
		NoTLS     bool
		NoDelay   bool
	}
)

var DefaultClient = &Client{Connector: HTTPConnector(nil), Transporter: TCPTransporter()}

func Dial(addr string, options ...DialOption) (net.Conn, error) {
	return DefaultClient.Dial(addr, options...)
}

func Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return DefaultClient.Handshake(conn, options...)
}

func Connect(conn net.Conn, addr string) (net.Conn, error) {
	return DefaultClient.Connect(conn, addr)
}

func ChainDialOption(chain *Chain) DialOption {
	return func(opts *DialOptions) {
		opts.Chain = chain
	}
}

func AddrHandshakeOption(addr string) HandshakeOption {
	return func(opts *HandshakeOptions) {
		opts.Addr = addr
	}
}

func AddrConnectOption(addr string) ConnectOption {
	return func(opts *ConnectOptions) {
		opts.Addr = addr
	}
}
