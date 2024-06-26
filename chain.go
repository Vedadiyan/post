package post

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

type (
	ChainOption func(opts *ChainOptions)

	Chain struct {
		isRoute    bool
		Retries    int
		Mark       int
		Interface  string
		nodeGroups []*NodeGroup
		route      []Node
	}

	ChainOptions struct {
		Retries  int
		Timeout  time.Duration
		Hosts    *Hosts
		Resolver Resolver
		Mark     int
	}
)

var (
	ErrEmptyChain = errors.New("empty chain")
)

func NewChain(nodes ...Node) *Chain {
	chain := &Chain{}
	for _, node := range nodes {
		chain.nodeGroups = append(chain.nodeGroups, NewNodeGroup(node))
	}
	return chain
}

func (c *Chain) newRoute(nodes ...Node) *Chain {
	route := NewChain(nodes...)
	route.isRoute = true
	if !c.IsEmpty() {
		route.Interface = c.Interface
		route.Mark = c.Mark
	}
	return route
}

func (c *Chain) Nodes() (nodes []Node) {
	for _, group := range c.nodeGroups {
		if ns := group.Nodes(); len(ns) > 0 {
			nodes = append(nodes, ns[0])
		}
	}
	return
}

func (c *Chain) NodeGroups() []*NodeGroup {
	return c.nodeGroups
}

func (c *Chain) LastNode() Node {
	if c.IsEmpty() {
		return Node{}
	}
	group := c.nodeGroups[len(c.nodeGroups)-1]
	return group.GetNode(0)
}

func (c *Chain) LastNodeGroup() *NodeGroup {
	if c.IsEmpty() {
		return nil
	}
	return c.nodeGroups[len(c.nodeGroups)-1]
}

func (c *Chain) AddNode(nodes ...Node) {
	if c == nil {
		return
	}
	for _, node := range nodes {
		c.nodeGroups = append(c.nodeGroups, NewNodeGroup(node))
	}
}

func (c *Chain) AddNodeGroup(groups ...*NodeGroup) {
	if c == nil {
		return
	}
	c.nodeGroups = append(c.nodeGroups, groups...)
}

func (c *Chain) IsEmpty() bool {
	return c == nil || len(c.nodeGroups) == 0
}

func (c *Chain) Dial(address string, opts ...ChainOption) (conn net.Conn, err error) {
	return c.DialContext(context.Background(), "tcp", address, opts...)
}

func (c *Chain) DialContext(ctx context.Context, network, address string, opts ...ChainOption) (conn net.Conn, err error) {
	options := &ChainOptions{}
	for _, opt := range opts {
		opt(options)
	}

	retries := 1
	if c != nil && c.Retries > 0 {
		retries = c.Retries
	}
	if options.Retries > 0 {
		retries = options.Retries
	}

	for i := 0; i < retries; i++ {
		conn, err = c.dialWithOptions(ctx, network, address, options)
		if err == nil {
			break
		}
	}
	return
}

func (c *Chain) dialWithOptions(ctx context.Context, network, address string, options *ChainOptions) (net.Conn, error) {
	if options == nil {
		options = &ChainOptions{}
	}
	if c == nil {
		c = &Chain{}
	}
	route, err := c.selectRouteFor(address)
	if err != nil {
		return nil, err
	}

	ipAddr := address
	if address != "" {
		ipAddr = c.resolve(address, options.Resolver, options.Hosts)
		if ipAddr == "" {
			return nil, fmt.Errorf("resolver: domain %s does not exists", address)
		}
	}

	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DialTimeout
	}

	var controlFunction func(_ string, _ string, c syscall.RawConn) error = nil
	if c.Mark > 0 {
		controlFunction = func(_, _ string, cc syscall.RawConn) error {
			return cc.Control(func(fd uintptr) {
				_ = setSocketMark(int(fd), c.Mark)
			})
		}
	}

	if c.Interface != "" {
		controlFunction = func(_, _ string, cc syscall.RawConn) error {
			return cc.Control(func(fd uintptr) {
				_ = setSocketInterface(int(fd), c.Interface)
			})
		}
	}

	if route.IsEmpty() {
		switch network {
		case "udp", "udp4", "udp6":
			if address == "" {
				return net.ListenUDP(network, nil)
			}
		default:
		}
		d := &net.Dialer{
			Timeout: timeout,
			Control: controlFunction,
		}
		return d.DialContext(ctx, network, ipAddr)
	}

	conn, err := route.getConn(ctx)
	if err != nil {
		return nil, err
	}

	cOpts := append([]ConnectOption{AddrConnectOption(address)}, route.LastNode().ConnectOptions...)
	cc, err := route.LastNode().Client.ConnectContext(ctx, conn, network, ipAddr, cOpts...)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

func (*Chain) resolve(addr string, resolver Resolver, hosts *Hosts) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}

	if ip := hosts.Lookup(host); ip != nil {
		return net.JoinHostPort(ip.String(), port)
	}
	if resolver != nil {
		ips, _ := resolver.Resolve(host)
		if len(ips) == 0 {
			return ""
		}
		return net.JoinHostPort(ips[0].String(), port)
	}
	return addr
}

func (c *Chain) Conn(opts ...ChainOption) (conn net.Conn, err error) {
	options := &ChainOptions{}
	for _, opt := range opts {
		opt(options)
	}

	ctx := context.Background()

	retries := 1
	if c != nil && c.Retries > 0 {
		retries = c.Retries
	}
	if options.Retries > 0 {
		retries = options.Retries
	}

	for i := 0; i < retries; i++ {
		var route *Chain
		route, err = c.selectRoute()
		if err != nil {
			continue
		}
		conn, err = route.getConn(ctx)
		if err == nil {
			break
		}
	}
	return
}

func (c *Chain) getConn(ctx context.Context) (conn net.Conn, err error) {
	if c.IsEmpty() {
		err = ErrEmptyChain
		return
	}
	nodes := c.Nodes()
	node := nodes[0]

	cc, err := node.Client.Dial(node.Addr, node.DialOptions...)
	if err != nil {
		node.MarkDead()
		return
	}

	cn, err := node.Client.Handshake(cc, node.HandshakeOptions...)
	if err != nil {
		cc.Close()
		node.MarkDead()
		return
	}
	node.ResetDead()

	preNode := node
	for _, node := range nodes[1:] {
		var cc net.Conn
		cc, err = preNode.Client.ConnectContext(ctx, cn, "tcp", node.Addr, preNode.ConnectOptions...)
		if err != nil {
			cn.Close()
			node.MarkDead()
			return
		}
		cc, err = node.Client.Handshake(cc, node.HandshakeOptions...)
		if err != nil {
			cn.Close()
			node.MarkDead()
			return
		}
		node.ResetDead()

		cn = cc
		preNode = node
	}

	conn = cn
	return
}

func (c *Chain) selectRoute() (route *Chain, err error) {
	return c.selectRouteFor("")
}

func (c *Chain) selectRouteFor(addr string) (route *Chain, err error) {
	if c.IsEmpty() {
		return c.newRoute(), nil
	}
	if c.isRoute {
		return c, nil
	}

	route = c.newRoute()
	var nl []Node

	for _, group := range c.nodeGroups {
		var node Node
		node, err = group.Next()
		if err != nil {
			return
		}

		if node.Client.Transporter.Multiplex() {
			node.DialOptions = append(node.DialOptions,
				ChainDialOption(route),
			)
			route = c.newRoute()
		}

		route.AddNode(node)
		nl = append(nl, node)
	}

	route.route = nl

	return
}

func RetryChainOption(retries int) ChainOption {
	return func(opts *ChainOptions) {
		opts.Retries = retries
	}
}

func TimeoutChainOption(timeout time.Duration) ChainOption {
	return func(opts *ChainOptions) {
		opts.Timeout = timeout
	}
}

func HostsChainOption(hosts *Hosts) ChainOption {
	return func(opts *ChainOptions) {
		opts.Hosts = hosts
	}
}

func ResolverChainOption(resolver Resolver) ChainOption {
	return func(opts *ChainOptions) {
		opts.Resolver = resolver
	}
}
