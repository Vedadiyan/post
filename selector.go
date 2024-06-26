package post

import (
	"errors"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type (
	FIFOStrategy  struct{}
	InvalidFilter struct{}
	NodeSelector  interface {
		Select(nodes []Node, opts ...SelectOption) (Node, error)
	}
	defaultSelector struct {
	}
	SelectOption func(*SelectOptions)

	SelectOptions struct {
		Filters  []Filter
		Strategy Strategy
	}
	RoundStrategy struct {
		counter uint64
	}
	Strategy interface {
		Apply([]Node) Node
		String() string
	}
	RandomStrategy struct {
		Seed int64
		rand *rand.Rand
		once sync.Once
		mux  sync.Mutex
	}
	Filter interface {
		Filter([]Node) []Node
		String() string
	}
	FailFilter struct {
		MaxFails    int
		FailTimeout time.Duration
	}
	FastestFilter struct {
		mu            sync.Mutex
		pinger        *net.Dialer
		pingResult    map[int]int
		pingResultTTL map[int]int64

		topCount int
	}
	failMarker struct {
		failTime  int64
		failCount uint32
		mux       sync.RWMutex
	}
)

const (
	DefaultMaxFails    = 1
	DefaultFailTimeout = 30 * time.Second
)

var (
	ErrNoneAvailable = errors.New("none node available")
)

func (s *defaultSelector) Select(nodes []Node, opts ...SelectOption) (Node, error) {
	sopts := SelectOptions{}
	for _, opt := range opts {
		opt(&sopts)
	}

	for _, filter := range sopts.Filters {
		nodes = filter.Filter(nodes)
	}
	if len(nodes) == 0 {
		return Node{}, ErrNoneAvailable
	}
	strategy := sopts.Strategy
	if strategy == nil {
		strategy = &RoundStrategy{}
	}
	return strategy.Apply(nodes), nil
}

func WithFilter(f ...Filter) SelectOption {
	return func(o *SelectOptions) {
		o.Filters = append(o.Filters, f...)
	}
}

func WithStrategy(s Strategy) SelectOption {
	return func(o *SelectOptions) {
		o.Strategy = s
	}
}

func NewStrategy(s string) Strategy {
	switch s {
	case "random":
		return &RandomStrategy{}
	case "fifo":
		return &FIFOStrategy{}
	case "round":
		fallthrough
	default:
		return &RoundStrategy{}
	}
}

func (s *RoundStrategy) Apply(nodes []Node) Node {
	if len(nodes) == 0 {
		return Node{}
	}

	n := atomic.AddUint64(&s.counter, 1) - 1
	return nodes[int(n%uint64(len(nodes)))]
}

func (s *RoundStrategy) String() string {
	return "round"
}

func (s *RandomStrategy) Apply(nodes []Node) Node {
	s.once.Do(func() {
		seed := s.Seed
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		s.rand = rand.New(rand.NewSource(seed))
	})
	if len(nodes) == 0 {
		return Node{}
	}

	s.mux.Lock()
	r := s.rand.Int()
	s.mux.Unlock()

	return nodes[r%len(nodes)]
}

func (s *RandomStrategy) String() string {
	return "random"
}

func (s *FIFOStrategy) Apply(nodes []Node) Node {
	if len(nodes) == 0 {
		return Node{}
	}
	return nodes[0]
}

func (s *FIFOStrategy) String() string {
	return "fifo"
}

func (f *FailFilter) Filter(nodes []Node) []Node {
	maxFails := f.MaxFails
	if maxFails == 0 {
		maxFails = DefaultMaxFails
	}
	failTimeout := f.FailTimeout
	if failTimeout == 0 {
		failTimeout = DefaultFailTimeout
	}

	if len(nodes) <= 1 || maxFails < 0 {
		return nodes
	}
	nl := []Node{}
	for i := range nodes {
		marker := nodes[i].marker.Clone()

		if marker.FailCount() < uint32(maxFails) ||
			time.Since(time.Unix(marker.FailTime(), 0)) >= failTimeout {
			nl = append(nl, nodes[i])
		}
	}
	return nl
}

func (f *FailFilter) String() string {
	return "fail"
}

func NewFastestFilter(pingTimeOut int, topCount int) *FastestFilter {
	if pingTimeOut == 0 {
		pingTimeOut = 3000
	}
	return &FastestFilter{
		mu:            sync.Mutex{},
		pinger:        &net.Dialer{Timeout: time.Millisecond * time.Duration(pingTimeOut)},
		pingResult:    make(map[int]int, 0),
		pingResultTTL: make(map[int]int64, 0),
		topCount:      topCount,
	}
}

func (f *FastestFilter) Filter(nodes []Node) []Node {

	if f.topCount == 0 {
		return nodes
	}

	now := time.Now().Unix()

	var getNodeLatency = func(node Node) int {
		f.mu.Lock()
		defer f.mu.Unlock()

		if f.pingResultTTL[node.ID] < now {
			f.pingResultTTL[node.ID] = now + 5

			go func(node Node) {
				latency := f.doTcpPing(node.Addr)
				r := rand.New(rand.NewSource(time.Now().UnixNano()))
				ttl := 300 - int64(120*r.Float64())

				f.mu.Lock()
				defer f.mu.Unlock()

				f.pingResult[node.ID] = latency
				f.pingResultTTL[node.ID] = now + ttl
			}(node)
		}
		return f.pingResult[node.ID]
	}

	sort.Slice(nodes, func(i, j int) bool {
		return getNodeLatency(nodes[i]) < getNodeLatency(nodes[j])
	})

	if len(nodes) <= f.topCount {
		return nodes
	}

	return nodes[0:f.topCount]
}

func (f *FastestFilter) String() string {
	return "fastest"
}

func (f *FastestFilter) doTcpPing(address string) int {
	start := time.Now()
	conn, err := f.pinger.Dial("tcp", address)
	elapsed := time.Since(start)

	if err == nil {
		_ = conn.Close()
	}

	latency := int(elapsed.Milliseconds())
	return latency
}

func (f *InvalidFilter) Filter(nodes []Node) []Node {
	nl := []Node{}
	for i := range nodes {
		_, sport, _ := net.SplitHostPort(nodes[i].Addr)
		if port, _ := strconv.Atoi(sport); port > 0 {
			nl = append(nl, nodes[i])
		}
	}
	return nl
}

func (f *InvalidFilter) String() string {
	return "invalid"
}

func (m *failMarker) FailTime() int64 {
	if m == nil {
		return 0
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	return m.failTime
}

func (m *failMarker) FailCount() uint32 {
	if m == nil {
		return 0
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	return m.failCount
}

func (m *failMarker) Mark() {
	if m == nil {
		return
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	m.failTime = time.Now().Unix()
	m.failCount++
}

func (m *failMarker) Reset() {
	if m == nil {
		return
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	m.failTime = 0
	m.failCount = 0
}

func (m *failMarker) Clone() *failMarker {
	if m == nil {
		return nil
	}

	m.mux.RLock()
	defer m.mux.RUnlock()

	fc, ft := m.failCount, m.failTime

	return &failMarker{
		failCount: fc,
		failTime:  ft,
	}
}
