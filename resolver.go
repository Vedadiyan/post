package post

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

type (
	NameServerOption func(*nameServerOptions)
	ResolverOption   func(*resolverOptions)
	ExchangerOption  func(opts *exchangerOptions)
	Resolver         interface {
		Init(opts ...ResolverOption) error

		Resolve(host string) ([]net.IP, error)

		Exchange(ctx context.Context, query []byte) (reply []byte, err error)
	}
	nameServerOptions struct {
		timeout time.Duration
		chain   *Chain
	}
	dohExchanger struct {
		endpoint *url.URL
		client   *http.Client
		options  exchangerOptions
	}
	resolverOptions struct {
		chain   *Chain
		timeout time.Duration
		ttl     time.Duration
		prefer  string
		srcIP   net.IP
	}
	exchangerOptions struct {
		chain   *Chain
		timeout time.Duration
	}
	dnsExchanger struct {
		addr    string
		options exchangerOptions
	}
	dnsTCPExchanger struct {
		addr    string
		options exchangerOptions
	}
	dotExchanger struct {
		addr      string
		tlsConfig *tls.Config
		options   exchangerOptions
	}
	NameServer struct {
		Addr     string
		Protocol string
		Hostname string
	}
	ReloadResolver interface {
		Resolver
	}
	Exchanger interface {
		Exchange(ctx context.Context, query []byte) ([]byte, error)
	}
)

var (
	DefaultResolverTimeout = 5 * time.Second
)

func TimeoutNameServerOption(timeout time.Duration) NameServerOption {
	return func(opts *nameServerOptions) {
		opts.timeout = timeout
	}
}

func ChainNameServerOption(chain *Chain) NameServerOption {
	return func(opts *nameServerOptions) {
		opts.chain = chain
	}
}

func (ns *NameServer) String() string {
	addr := ns.Addr
	prot := ns.Protocol
	if prot == "" {
		prot = "udp"
	}
	return fmt.Sprintf("%s/%s", addr, prot)
}

func ChainResolverOption(chain *Chain) ResolverOption {
	return func(opts *resolverOptions) {
		opts.chain = chain
	}
}

func TimeoutResolverOption(timeout time.Duration) ResolverOption {
	return func(opts *resolverOptions) {
		opts.timeout = timeout
	}
}

func TTLResolverOption(ttl time.Duration) ResolverOption {
	return func(opts *resolverOptions) {
		opts.ttl = ttl
	}
}

func PreferResolverOption(prefer string) ResolverOption {
	return func(opts *resolverOptions) {
		opts.prefer = prefer
	}
}

func SrcIPResolverOption(ip net.IP) ResolverOption {
	return func(opts *resolverOptions) {
		opts.srcIP = ip
	}
}

func ChainExchangerOption(chain *Chain) ExchangerOption {
	return func(opts *exchangerOptions) {
		opts.chain = chain
	}
}

func TimeoutExchangerOption(timeout time.Duration) ExchangerOption {
	return func(opts *exchangerOptions) {
		opts.timeout = timeout
	}
}

func NewDNSExchanger(addr string, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	return &dnsExchanger{
		addr:    addr,
		options: options,
	}
}

func (ex *dnsExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	t := time.Now()
	c, err := ex.options.chain.DialContext(ctx,
		"udp", ex.addr,
		TimeoutChainOption(ex.options.timeout),
	)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(ex.options.timeout - time.Since(t)))
	defer c.Close()

	conn := &dns.Conn{
		Conn:    c,
		UDPSize: 1024,
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	return mr.Pack()
}

func NewDNSTCPExchanger(addr string, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	return &dnsTCPExchanger{
		addr:    addr,
		options: options,
	}
}

func (ex *dnsTCPExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	t := time.Now()
	c, err := ex.options.chain.DialContext(ctx,
		"tcp", ex.addr,
		TimeoutChainOption(ex.options.timeout),
	)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(ex.options.timeout - time.Since(t)))
	defer c.Close()

	conn := &dns.Conn{
		Conn: c,
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	return mr.Pack()
}

func NewDoTExchanger(addr string, tlsConfig *tls.Config, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return &dotExchanger{
		addr:      addr,
		tlsConfig: tlsConfig,
		options:   options,
	}
}

func (ex *dotExchanger) dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = ex.options.chain.DialContext(ctx,
		network, address,
		TimeoutChainOption(ex.options.timeout),
	)
	if err != nil {
		return
	}
	conn = tls.Client(conn, ex.tlsConfig)

	return
}

func (ex *dotExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	t := time.Now()
	c, err := ex.dial(ctx, "tcp", ex.addr)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(ex.options.timeout - time.Since(t)))
	defer c.Close()

	conn := &dns.Conn{
		Conn: c,
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	return mr.Pack()
}

func NewDoHExchanger(urlStr *url.URL, tlsConfig *tls.Config, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}
	ex := &dohExchanger{
		endpoint: urlStr,
		options:  options,
	}

	ex.client = &http.Client{
		Timeout: options.timeout,
		Transport: &http.Transport{

			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   options.timeout,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           ex.dialContext,
		},
	}

	return ex
}

func (ex *dohExchanger) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return ex.options.chain.DialContext(ctx,
		network, address,
		TimeoutChainOption(ex.options.timeout),
	)
}

func (ex *dohExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", ex.endpoint.String(), bytes.NewBuffer(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create an HTTPS request: %s", err)
	}

	req.Header.Add("Content-Type", "application/dns-message")
	req.Host = ex.endpoint.Hostname()

	client := ex.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform an HTTPS request: %s", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status code %d", resp.StatusCode)
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body: %s", err)
	}

	return buf, nil
}
