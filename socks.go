package post

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/gosocks4"
	"github.com/go-gost/gosocks5"
	smux "github.com/xtaci/smux"
)

type (
	socks5MuxBindConnector struct{}
	socks4Connector        struct{}
	socks4aConnector       struct{}
	socks5HandshakeOption  func(opts *socks5HandshakeOptions)
	clientSelector         struct {
		methods   []uint8
		User      *url.Userinfo
		TLSConfig *tls.Config
	}
	serverSelector struct {
		methods []uint8

		Authenticator Authenticator
		TLSConfig     *tls.Config
	}
	socks5Connector struct {
		User *url.Userinfo
	}
	socks5BindConnector struct {
		User *url.Userinfo
	}
	socks5MuxBindTransporter struct {
		bindAddr     string
		sessions     map[string]*muxSession
		sessionMutex sync.Mutex
	}
	socks5UDPConnector struct {
		User *url.Userinfo
	}
	socks5UDPTunConnector struct {
		User *url.Userinfo
	}
	socks5Handler struct {
		selector *serverSelector
		options  *HandlerOptions
	}
	socks4Handler struct {
		options *HandlerOptions
	}
	socks5HandshakeOptions struct {
		selector gosocks5.Selector
		user     *url.Userinfo
		noTLS    bool
	}
	socks5UDPTunnelConn struct {
		net.Conn
		taddr net.Addr
	}
	socks5BindConn struct {
		raddr net.Addr
		laddr net.Addr
		net.Conn
		handshaked   bool
		handshakeMux sync.Mutex
	}
	socks5UDPConn struct {
		*net.UDPConn
		taddr net.Addr
	}
	muxBindClientConn struct {
		nopConn
		session *muxSession
	}
)

const (
	MethodTLS uint8 = 0x80

	MethodTLSAuth uint8 = 0x82

	MethodMux        = 0x88
	CmdMuxBind uint8 = 0xF2

	CmdUDPTun uint8 = 0xF3
)

var (
	_ net.PacketConn = (*socks5UDPTunnelConn)(nil)
)

func (selector *clientSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *clientSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *clientSelector) Select(methods ...uint8) (method uint8) {
	return
}

func (selector *clientSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Client(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Client(conn, selector.TLSConfig)
		}

		var username, password string
		if selector.User != nil {
			username = selector.User.Username()
			password, _ = selector.User.Password()
		}

		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, username, password)
		if err := req.Write(conn); err != nil {

			return nil, err
		}
		resp, err := gosocks5.ReadUserPassResponse(conn)
		if err != nil {

			return nil, err
		}
		if resp.Status != gosocks5.Succeeded {
			return nil, gosocks5.ErrAuthFailure
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	method = gosocks5.MethodNoAuth
	for _, m := range methods {
		if m == MethodTLS {
			method = m
			break
		}
	}

	if selector.Authenticator != nil {
		if method == gosocks5.MethodNoAuth {
			method = gosocks5.MethodUserPass
		}
		if method == MethodTLS {
			method = MethodTLSAuth
		}
	}

	return
}

func (selector *serverSelector) OnSelected(method uint8, conn net.Conn) (net.Conn, error) {
	switch method {
	case MethodTLS:
		conn = tls.Server(conn, selector.TLSConfig)

	case gosocks5.MethodUserPass, MethodTLSAuth:
		if method == MethodTLSAuth {
			conn = tls.Server(conn, selector.TLSConfig)
		}

		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {

			return nil, err
		}

		if selector.Authenticator != nil && !selector.Authenticator.Authenticate(req.Username, req.Password) {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {

				return nil, err
			}

			return nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {

			return nil, err
		}
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

func SOCKS5Connector(user *url.Userinfo) Connector {
	return &socks5Connector{User: user}
}

func (c *socks5Connector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *socks5Connector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		cnr := &socks5UDPTunConnector{User: c.User}
		return cnr.ConnectContext(ctx, conn, network, address, options...)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn,
		selectorSocks5HandshakeOption(opts.Selector),
		userSocks5HandshakeOption(user),
		noTLSSocks5HandshakeOption(opts.NoTLS),
	)
	if err != nil {
		return nil, err
	}
	conn = cc

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)
	req := gosocks5.NewRequest(gosocks5.CmdConnect, &gosocks5.Addr{
		Type: gosocks5.AddrDomain,
		Host: host,
		Port: uint16(p),
	})
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("service unavailable")
	}

	return conn, nil
}

func SOCKS5BindConnector(user *url.Userinfo) Connector {
	return &socks5BindConnector{User: user}
}

func (c *socks5BindConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *socks5BindConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn,
		selectorSocks5HandshakeOption(opts.Selector),
		userSocks5HandshakeOption(user),
		noTLSSocks5HandshakeOption(opts.NoTLS),
	)
	if err != nil {
		return nil, err
	}
	conn = cc

	laddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {

		return nil, err
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: laddr.IP.String(),
		Port: uint16(laddr.Port),
	})

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if reply.Rep != gosocks5.Succeeded {

		return nil, fmt.Errorf("SOCKS5 bind on %s failure", address)
	}
	baddr, err := net.ResolveTCPAddr("tcp", reply.Addr.String())
	if err != nil {
		return nil, err
	}

	return &socks5BindConn{Conn: conn, laddr: baddr}, nil
}

func Socks5MuxBindConnector() Connector {
	return &socks5MuxBindConnector{}
}

func (c *socks5MuxBindConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *socks5MuxBindConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	accepter, ok := conn.(Accepter)
	if !ok {
		return nil, errors.New("wrong connection type")
	}

	return accepter.Accept()
}

func SOCKS5MuxBindTransporter(bindAddr string) Transporter {
	return &socks5MuxBindTransporter{
		bindAddr: bindAddr,
		sessions: make(map[string]*muxSession),
	}
}

func (tr *socks5MuxBindTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	session, ok := tr.sessions[addr]
	if session != nil && session.IsClosed() {
		delete(tr.sessions, addr)
		ok = false
	}
	if !ok {
		if opts.Chain == nil {
			conn, err = net.DialTimeout("tcp", addr, timeout)
		} else {
			conn, err = opts.Chain.Dial(addr)
		}
		if err != nil {
			return
		}
		session = &muxSession{conn: conn}
		tr.sessions[addr] = session
	}
	return session.conn, nil
}

func (tr *socks5MuxBindTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}

	tr.sessionMutex.Lock()
	defer tr.sessionMutex.Unlock()

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	session, ok := tr.sessions[opts.Addr]
	if !ok || session.session == nil {
		s, err := tr.initSession(conn, tr.bindAddr, opts)
		if err != nil {
			conn.Close()
			delete(tr.sessions, opts.Addr)
			return nil, err
		}
		session = s
		tr.sessions[opts.Addr] = session
	}

	return &muxBindClientConn{session: session}, nil
}

func (tr *socks5MuxBindTransporter) initSession(conn net.Conn, addr string, opts *HandshakeOptions) (*muxSession, error) {
	if opts == nil {
		opts = &HandshakeOptions{}
	}

	cc, err := socks5Handshake(conn,
		userSocks5HandshakeOption(opts.User),
	)
	if err != nil {
		return nil, err
	}
	conn = cc

	bindAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	req := gosocks5.NewRequest(CmdMuxBind, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
		Host: bindAddr.IP.String(),
		Port: uint16(bindAddr.Port),
	})

	if err = req.Write(conn); err != nil {
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if reply.Rep != gosocks5.Succeeded {

		return nil, fmt.Errorf("SOCKS5 mbind on %s failure", addr)
	}
	_, err = net.ResolveTCPAddr("tcp", reply.Addr.String())
	if err != nil {
		return nil, err
	}

	session, err := smux.Server(conn, smux.DefaultConfig())
	if err != nil {
		return nil, err
	}
	return &muxSession{conn: conn, session: session}, nil
}

func (tr *socks5MuxBindTransporter) Multiplex() bool {
	return true
}

func SOCKS5UDPConnector(user *url.Userinfo) Connector {
	return &socks5UDPConnector{User: user}
}

func (c *socks5UDPConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "udp", address, options...)
}

func (c *socks5UDPConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	user := opts.User
	if user == nil {
		user = c.User
	}
	cc, err := socks5Handshake(conn,
		selectorSocks5HandshakeOption(opts.Selector),
		userSocks5HandshakeOption(user),
		noTLSSocks5HandshakeOption(opts.NoTLS),
	)
	if err != nil {
		return nil, err
	}
	conn = cc

	taddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	req := gosocks5.NewRequest(gosocks5.CmdUdp, &gosocks5.Addr{
		Type: gosocks5.AddrIPv4,
	})

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if reply.Rep != gosocks5.Succeeded {

		return nil, fmt.Errorf("SOCKS5 udp relay failure")
	}
	baddr, err := net.ResolveUDPAddr("udp", reply.Addr.String())
	if err != nil {
		return nil, err
	}

	uc, err := net.DialUDP("udp", nil, baddr)
	if err != nil {
		return nil, err
	}

	return &socks5UDPConn{UDPConn: uc, taddr: taddr}, nil
}

func SOCKS5UDPTunConnector(user *url.Userinfo) Connector {
	return &socks5UDPTunConnector{User: user}
}

func (c *socks5UDPTunConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "udp", address, options...)
}

func (c *socks5UDPTunConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	user := opts.User
	if user == nil {
		user = c.User
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	taddr, _ := net.ResolveUDPAddr("udp", address)
	return newSocks5UDPTunnelConn(conn,
		nil, taddr,
		selectorSocks5HandshakeOption(opts.Selector),
		userSocks5HandshakeOption(user),
		noTLSSocks5HandshakeOption(opts.NoTLS),
	)
}

func SOCKS4Connector() Connector {
	return &socks4Connector{}
}

func (c *socks4Connector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *socks4Connector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	taddr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, err
	}
	if len(taddr.IP) == 0 {
		taddr.IP = net.IPv4zero
	}

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{
			Type: gosocks4.AddrIPv4,
			Host: taddr.IP.String(),
			Port: uint16(taddr.Port),
		}, nil,
	)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4] %d", reply.Code)
	}

	return conn, nil
}

func SOCKS4AConnector() Connector {
	return &socks4aConnector{}
}

func (c *socks4aConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *socks4aConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, _ := strconv.Atoi(port)

	req := gosocks4.NewRequest(gosocks4.CmdConnect,
		&gosocks4.Addr{Type: gosocks4.AddrDomain, Host: host, Port: uint16(p)}, nil)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reply, err := gosocks4.ReadReply(conn)
	if err != nil {
		return nil, err
	}

	if reply.Code != gosocks4.Granted {
		return nil, fmt.Errorf("[socks4a] %d", reply.Code)
	}

	return conn, nil
}

func SOCKS5Handler(opts ...HandlerOption) Handler {
	h := &socks5Handler{}
	h.Init(opts...)

	return h
}

func (h *socks5Handler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}

	tlsConfig := h.options.TLSConfig
	if tlsConfig == nil {
		tlsConfig = DefaultTLSConfig
	}
	h.selector = &serverSelector{

		Authenticator: h.options.Authenticator,
		TLSConfig:     tlsConfig,
	}

	h.selector.AddMethod(
		gosocks5.MethodNoAuth,
		gosocks5.MethodUserPass,
		MethodTLS,
		MethodTLSAuth,
	)
}

func (h *socks5Handler) Handle(conn net.Conn) {
	defer conn.Close()

	conn = gosocks5.ServerConn(conn, h.selector)
	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		return
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		h.handleConnect(conn, req)

	case gosocks5.CmdBind:
		h.handleBind(conn, req)

	case gosocks5.CmdUdp:
		h.handleUDPRelay(conn, req)

	case CmdMuxBind:
		h.handleMuxBind(conn, req)

	case CmdUDPTun:
		h.handleUDPTunnel(conn, req)

	default:
	}
}

func (h *socks5Handler) handleConnect(conn net.Conn, req *gosocks5.Request) {
	host := req.Addr.String()

	if !Can("tcp", host, h.options.Whitelist, h.options.Blacklist) {
		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(conn)
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(host)
		if err != nil {
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", host)

		cc, err = route.Dial(host,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
	}

	if err != nil {
		rep := gosocks5.NewReply(gosocks5.HostUnreachable, nil)
		rep.Write(conn)
		return
	}
	defer cc.Close()

	rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
	if err := rep.Write(conn); err != nil {
		return
	}

	transport(conn, cc)

}

func (h *socks5Handler) handleBind(conn net.Conn, req *gosocks5.Request) {
	addr := req.Addr.String()

	if h.options.Chain.IsEmpty() {
		if !Can("rtcp", addr, h.options.Whitelist, h.options.Blacklist) {
			return
		}
		h.bindOn(conn, addr)
		return
	}

	cc, err := h.options.Chain.Conn()
	if err != nil {
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		return
	}

	defer cc.Close()
	req.Write(cc)

	transport(conn, cc)

}

func (h *socks5Handler) bindOn(conn net.Conn, addr string) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr)
	if err != nil {
		gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
		return
	}

	socksAddr := toSocksAddr(ln.Addr())

	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {
		ln.Close()
		return
	}

	var pconn net.Conn
	accept := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer ln.Close()

			c, err := ln.AcceptTCP()
			if err != nil {
				errc <- err
				return
			}
			pconn = c
		}()

		return errc
	}

	pc1, pc2 := net.Pipe()
	pipe := func() <-chan error {
		errc := make(chan error, 1)

		go func() {
			defer close(errc)
			defer pc1.Close()

			errc <- transport(conn, pc1)
		}()

		return errc
	}

	defer pc2.Close()

	for {
		select {
		case <-accept():
			defer pconn.Close()
			_ = gosocks5.NewReply(gosocks5.Succeeded, toSocksAddr(pconn.RemoteAddr()))
			return
		case <-pipe():
			ln.Close()
			return
		}
	}
}

func (h *socks5Handler) handleUDPRelay(conn net.Conn, req *gosocks5.Request) {
	addr := req.Addr.String()
	if !Can("udp", addr, h.options.Whitelist, h.options.Blacklist) {

		rep := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		rep.Write(conn)
		return
	}

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: conn.LocalAddr().(*net.TCPAddr).IP, Port: 0})
	if err != nil {

		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		return
	}
	defer relay.Close()

	socksAddr := toSocksAddr(relay.LocalAddr())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {

		return
	}

	if h.options.Chain.IsEmpty() {
		peer, er := net.ListenUDP("udp", nil)
		if er != nil {

			return
		}
		defer peer.Close()

		go h.transportUDP(relay, peer)
		_ = h.discardClientData(conn)
		return
	}

	cc, err := h.options.Chain.Conn()

	if err != nil {

		return
	}
	defer cc.Close()

	cc, err = socks5Handshake(cc, userSocks5HandshakeOption(h.options.Chain.LastNode().User))
	if err != nil {

		return
	}

	cc.SetWriteDeadline(time.Now().Add(WriteTimeout))
	r := gosocks5.NewRequest(CmdUDPTun, nil)
	if err := r.Write(cc); err != nil {

		return
	}
	cc.SetWriteDeadline(time.Time{})
	cc.SetReadDeadline(time.Now().Add(ReadTimeout))
	reply, err = gosocks5.ReadReply(cc)
	if err != nil {

		return
	}

	if reply.Rep != gosocks5.Succeeded {

		return
	}
	cc.SetReadDeadline(time.Time{})

	go h.tunnelClientUDP(relay, cc)
	_ = h.discardClientData(conn)

}

func (h *socks5Handler) discardClientData(conn net.Conn) (err error) {
	b := make([]byte, tinyBufferSize)
	for {
		_, err = conn.Read(b)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}

	}
	return
}

func (h *socks5Handler) transportUDP(relay, peer net.PacketConn) (err error) {
	errc := make(chan error, 2)

	var clientAddr net.Addr

	go func() {
		_b := mPool.Get().(*[]byte)
		b := *_b
		defer mPool.Put(&b)

		for {
			n, laddr, err := relay.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = laddr
			}
			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}

			raddr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue
			}
			if _, err := peer.WriteTo(dgram.Data, raddr); err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		_b := mPool.Get().(*[]byte)
		b := *_b
		defer mPool.Put(&b)

		for {
			n, raddr, err := peer.ReadFrom(b)
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				continue
			}
			buf := bytes.Buffer{}
			dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(0, 0, toSocksAddr(raddr)), b[:n])
			dgram.Write(&buf)
			if _, err := relay.WriteTo(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
		}
	}()

	<-errc
	return
}

func (h *socks5Handler) tunnelClientUDP(uc *net.UDPConn, cc net.Conn) (err error) {
	errc := make(chan error, 2)

	var clientAddr *net.UDPAddr

	go func() {
		_b := mPool.Get().(*[]byte)
		b := *_b
		defer mPool.Put(&b)

		for {
			n, addr, err := uc.ReadFromUDP(b)
			if err != nil {

				errc <- err
				return
			}

			dgram, err := gosocks5.ReadUDPDatagram(bytes.NewReader(b[:n]))
			if err != nil {
				errc <- err
				return
			}
			if clientAddr == nil {
				clientAddr = addr
			}
			dgram.Header.Rsv = uint16(len(dgram.Data))
			if err := dgram.Write(cc); err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {

				errc <- err
				return
			}

			if clientAddr == nil {
				continue
			}
			dgram.Header.Rsv = 0
			buf := bytes.Buffer{}
			dgram.Write(&buf)
			if _, err := uc.WriteToUDP(buf.Bytes(), clientAddr); err != nil {
				errc <- err
				return
			}
		}
	}()

	<-errc
	return
}

func (h *socks5Handler) handleUDPTunnel(conn net.Conn, req *gosocks5.Request) {

	if h.options.Chain.IsEmpty() {
		addr := req.Addr.String()

		if !Can("rudp", addr, h.options.Whitelist, h.options.Blacklist) {

			return
		}

		bindAddr, _ := net.ResolveUDPAddr("udp", addr)
		uc, err := net.ListenUDP("udp", bindAddr)
		if err != nil {

			return
		}
		defer uc.Close()

		socksAddr := toSocksAddr(uc.LocalAddr())
		socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
		if err := reply.Write(conn); err != nil {

			return
		}

		h.tunnelServerUDP(conn, uc)

		return
	}

	cc, err := h.options.Chain.Conn()

	if err != nil {

		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)

		return
	}
	defer cc.Close()

	cc, err = socks5Handshake(cc, userSocks5HandshakeOption(h.options.Chain.LastNode().User))
	if err != nil {

		return
	}

	req.Write(cc)

	transport(conn, cc)

}

func (h *socks5Handler) tunnelServerUDP(cc net.Conn, pc net.PacketConn) (err error) {
	errc := make(chan error, 2)

	go func() {
		_b := mPool.Get().(*[]byte)
		b := *_b
		defer mPool.Put(&b)

		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {

				errc <- err
				return
			}
			dgram := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, toSocksAddr(addr)), b[:n])
			if err := dgram.Write(cc); err != nil {

				errc <- err
				return
			}
		}
	}()

	go func() {
		for {
			dgram, err := gosocks5.ReadUDPDatagram(cc)
			if err != nil {

				errc <- err
				return
			}

			addr, err := net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
			if err != nil {
				continue
			}
			if _, err := pc.WriteTo(dgram.Data, addr); err != nil {

				errc <- err
				return
			}
		}
	}()

	<-errc

	return
}

func (h *socks5Handler) handleMuxBind(conn net.Conn, req *gosocks5.Request) {
	if h.options.Chain.IsEmpty() {
		addr := req.Addr.String()
		if !Can("rtcp", addr, h.options.Whitelist, h.options.Blacklist) {

			return
		}
		h.muxBindOn(conn, addr)
		return
	}

	cc, err := h.options.Chain.Conn()
	if err != nil {

		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		reply.Write(conn)
		return
	}

	defer cc.Close()
	req.Write(cc)

	transport(conn, cc)

}

func (h *socks5Handler) muxBindOn(conn net.Conn, addr string) {
	bindAddr, _ := net.ResolveTCPAddr("tcp", addr)
	ln, err := net.ListenTCP("tcp", bindAddr)
	if err != nil {

		gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
		return
	}
	defer ln.Close()

	socksAddr := toSocksAddr(ln.Addr())

	socksAddr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
	reply := gosocks5.NewReply(gosocks5.Succeeded, socksAddr)
	if err := reply.Write(conn); err != nil {

		return
	}

	s, err := smux.Client(conn, smux.DefaultConfig())
	if err != nil {

		return
	}

	session := &muxSession{
		conn:    conn,
		session: s,
	}
	defer session.Close()

	go func() {
		for {
			conn, err := session.Accept()
			if err != nil {

				ln.Close()
				return
			}
			conn.Close()
		}
	}()

	for {
		cc, err := ln.Accept()
		if err != nil {

			return
		}

		go func(c net.Conn) {
			defer c.Close()

			sc, err := session.GetConn()
			if err != nil {

				return
			}
			defer sc.Close()

			transport(sc, c)
		}(cc)
	}
}

func toSocksAddr(addr net.Addr) *gosocks5.Addr {
	host := "0.0.0.0"
	port := 0
	addrType := gosocks5.AddrIPv4
	if addr != nil {
		h, p, _ := net.SplitHostPort(addr.String())
		host = h
		port, _ = strconv.Atoi(p)
		if strings.Count(host, ":") > 0 {
			addrType = gosocks5.AddrIPv6
		}
	}
	return &gosocks5.Addr{
		Type: addrType,
		Host: host,
		Port: uint16(port),
	}
}

func SOCKS4Handler(opts ...HandlerOption) Handler {
	h := &socks4Handler{}
	h.Init(opts...)

	return h
}

func (h *socks4Handler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}

	for _, opt := range options {
		opt(h.options)
	}
}

func (h *socks4Handler) Handle(conn net.Conn) {
	defer conn.Close()

	req, err := gosocks4.ReadRequest(conn)
	if err != nil {
		return
	}

	switch req.Cmd {
	case gosocks4.CmdConnect:
		h.handleConnect(conn, req)

	case gosocks4.CmdBind:

		h.handleBind(conn, req)
	}
}

func (h *socks4Handler) handleConnect(conn net.Conn, req *gosocks4.Request) {
	addr := req.Addr.String()

	if !Can("tcp", addr, h.options.Whitelist, h.options.Blacklist) {
		rep := gosocks4.NewReply(gosocks4.Rejected, nil)
		rep.Write(conn)
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(addr)
		if err != nil {
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", addr)

		cc, err = route.Dial(addr,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}

	}

	if err != nil {
		rep := gosocks4.NewReply(gosocks4.Failed, nil)
		rep.Write(conn)
		return
	}
	defer cc.Close()

	rep := gosocks4.NewReply(gosocks4.Granted, nil)
	if err := rep.Write(conn); err != nil {
		return
	}

	transport(conn, cc)

}

func (h *socks4Handler) handleBind(conn net.Conn, req *gosocks4.Request) {

	if h.options.Chain.IsEmpty() {
		reply := gosocks4.NewReply(gosocks4.Rejected, nil)
		reply.Write(conn)
		return
	}

	cc, err := h.options.Chain.Conn()

	if err != nil && err != ErrEmptyChain {

		reply := gosocks4.NewReply(gosocks4.Failed, nil)
		reply.Write(conn)
		return
	}

	defer cc.Close()

	req.Write(cc)

	transport(conn, cc)

}

func selectorSocks5HandshakeOption(selector gosocks5.Selector) socks5HandshakeOption {
	return func(opts *socks5HandshakeOptions) {
		opts.selector = selector
	}
}

func userSocks5HandshakeOption(user *url.Userinfo) socks5HandshakeOption {
	return func(opts *socks5HandshakeOptions) {
		opts.user = user
	}
}

func noTLSSocks5HandshakeOption(noTLS bool) socks5HandshakeOption {
	return func(opts *socks5HandshakeOptions) {
		opts.noTLS = noTLS
	}
}

func socks5Handshake(conn net.Conn, opts ...socks5HandshakeOption) (net.Conn, error) {
	options := socks5HandshakeOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	selector := options.selector
	if selector == nil {
		cs := &clientSelector{
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
			User:      options.user,
		}
		cs.AddMethod(
			gosocks5.MethodNoAuth,
			gosocks5.MethodUserPass,
		)
		if !options.noTLS {
			cs.AddMethod(MethodTLS)
		}
		selector = cs
	}

	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		return nil, err
	}
	return cc, nil
}

func newSocks5UDPTunnelConn(conn net.Conn, raddr, taddr net.Addr, opts ...socks5HandshakeOption) (net.Conn, error) {
	cc, err := socks5Handshake(conn, opts...)
	if err != nil {
		return nil, err
	}

	req := gosocks5.NewRequest(CmdUDPTun, toSocksAddr(raddr))
	if err := req.Write(cc); err != nil {
		return nil, err
	}

	reply, err := gosocks5.ReadReply(cc)
	if err != nil {
		return nil, err
	}

	if reply.Rep != gosocks5.Succeeded {
		return nil, errors.New("socks5 UDP tunnel failure")
	}

	_, err = net.ResolveUDPAddr("udp", reply.Addr.String())
	if err != nil {
		return nil, err
	}

	return &socks5UDPTunnelConn{
		Conn:  cc,
		taddr: taddr,
	}, nil
}

func (c *socks5UDPTunnelConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *socks5UDPTunnelConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	dgram, err := gosocks5.ReadUDPDatagram(c.Conn)
	if err != nil {
		return
	}
	n = copy(b, dgram.Data)
	addr, err = net.ResolveUDPAddr("udp", dgram.Header.Addr.String())
	return
}

func (c *socks5UDPTunnelConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.taddr)
}

func (c *socks5UDPTunnelConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	dgram := gosocks5.NewUDPDatagram(gosocks5.NewUDPHeader(uint16(len(b)), 0, toSocksAddr(addr)), b)
	if err = dgram.Write(c.Conn); err != nil {
		return
	}
	return len(b), nil
}

func (c *socks5BindConn) Handshake() (err error) {
	c.handshakeMux.Lock()
	defer c.handshakeMux.Unlock()

	if c.handshaked {
		return nil
	}

	c.handshaked = true

	rep, err := gosocks5.ReadReply(c.Conn)
	if err != nil {
		return fmt.Errorf("bind: read reply %v", err)
	}
	if rep.Rep != gosocks5.Succeeded {
		return fmt.Errorf("bind: peer connect failure")
	}
	c.raddr, err = net.ResolveTCPAddr("tcp", rep.Addr.String())
	return
}

func (c *socks5BindConn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	return c.Conn.Read(b)
}

func (c *socks5BindConn) Write(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	return c.Conn.Write(b)
}

func (c *socks5BindConn) LocalAddr() net.Addr {
	return c.laddr
}

func (c *socks5BindConn) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *socks5UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *socks5UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	_data := mPool.Get().(*[]byte)
	data := *_data
	defer mPool.Put(&data)

	n, err = c.UDPConn.Read(data)
	if err != nil {
		return
	}
	dg, err := gosocks5.ReadUDPDatagram(bytes.NewReader(data[:n]))
	if err != nil {
		return
	}

	n = copy(b, dg.Data)
	addr, err = net.ResolveUDPAddr("udp", dg.Header.Addr.String())

	return
}

func (c *socks5UDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.taddr)
}

func (c *socks5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	adr, err := gosocks5.NewAddr(addr.String())
	if err != nil {
		return 0, err
	}
	h := gosocks5.NewUDPHeader(0, 0, adr)
	dg := gosocks5.NewUDPDatagram(h, b)
	if err = dg.Write(c.UDPConn); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *muxBindClientConn) Accept() (net.Conn, error) {
	return c.session.Accept()
}
