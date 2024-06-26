package post

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

type nopConn struct{}

const Version = "2.12.0"

var (
	KeepAliveTime     = 180 * time.Second
	DialTimeout       = 5 * time.Second
	HandshakeTimeout  = 5 * time.Second
	ConnectTimeout    = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 10 * time.Second
	PingTimeout       = 30 * time.Second
	PingRetries       = 1
	DefaultTLSConfig  *tls.Config
	DefaultUserAgent  = "Chrome/78.0.3904.106"
	DefaultProxyAgent = "gost/" + Version
	DefaultMTU        = 1350
	tinyBufferSize    = 512
	mediumBufferSize  = 8 * 1024
	largeBufferSize   = 32 * 1024
	mPool             = sync.Pool{
		New: func() interface{} {
			val := make([]byte, mediumBufferSize)
			return &val
		},
	}
	lPool = sync.Pool{
		New: func() interface{} {
			val := make([]byte, largeBufferSize)
			return &val
		},
	}
)

func (c *nopConn) Read(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "nop", Source: nil, Addr: nil, Err: errors.New("read not supported")}
}

func (c *nopConn) Write(b []byte) (n int, err error) {
	return 0, &net.OpError{Op: "write", Net: "nop", Source: nil, Addr: nil, Err: errors.New("write not supported")}
}

func (c *nopConn) Close() error {
	return nil
}

func (c *nopConn) LocalAddr() net.Addr {
	return nil
}

func (c *nopConn) RemoteAddr() net.Addr {
	return nil
}

func (c *nopConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *nopConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *nopConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "nop", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
