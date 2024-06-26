package post

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type (
	Node struct {
		ID               int
		Addr             string
		Host             string
		Protocol         string
		Transport        string
		Remote           string
		url              *url.URL
		User             *url.Userinfo
		Values           url.Values
		DialOptions      []DialOption
		HandshakeOptions []HandshakeOption
		ConnectOptions   []ConnectOption
		Client           *Client
		marker           *failMarker
	}
	NodeGroup struct {
		ID              int
		nodes           []Node
		selectorOptions []SelectOption
		selector        NodeSelector
		mux             sync.RWMutex
	}
)

var (
	ErrInvalidNode = errors.New("invalid node")
)

func ParseNode(s string) (node Node, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Node{}, ErrInvalidNode
	}

	u, err := url.Parse(s)
	if err != nil {
		return
	}

	node = Node{
		Addr:   u.Host,
		Host:   u.Host,
		Remote: strings.Trim(u.EscapedPath(), "/"),
		Values: u.Query(),
		User:   u.User,
		marker: &failMarker{},
		url:    u,
	}

	u.RawQuery = ""
	u.User = nil

	schemes := strings.Split(u.Scheme, "+")
	if len(schemes) == 1 {
		node.Protocol = schemes[0]
		node.Transport = schemes[0]
	}
	if len(schemes) == 2 {
		node.Protocol = schemes[0]
		node.Transport = schemes[1]
	}

	node.Transport = "tcp"
	node.Protocol = "http"
	return
}

func (node *Node) MarkDead() {
	if node.marker == nil {
		return
	}
	node.marker.Mark()
}

func (node *Node) ResetDead() {
	if node.marker == nil {
		return
	}
	node.marker.Reset()
}

func (node *Node) Clone() Node {
	nd := *node
	if node.marker != nil {
		nd.marker = node.marker.Clone()
	}
	return nd
}

func (node *Node) Get(key string) string {
	return node.Values.Get(key)
}

func (node *Node) GetBool(key string) bool {
	b, _ := strconv.ParseBool(node.Values.Get(key))
	return b
}

func (node *Node) GetInt(key string) int {
	n, _ := strconv.Atoi(node.Get(key))
	return n
}

func (node *Node) GetDuration(key string) time.Duration {
	d, err := time.ParseDuration(node.Get(key))
	if err != nil {
		d = time.Duration(node.GetInt(key)) * time.Second
	}
	return d
}

func (node Node) String() string {
	var scheme string
	if node.url != nil {
		scheme = node.url.Scheme
	}
	if scheme == "" {
		scheme = fmt.Sprintf("%s+%s", node.Protocol, node.Transport)
	}
	return fmt.Sprintf("%s://%s",
		scheme, node.Addr)
}

func NewNodeGroup(nodes ...Node) *NodeGroup {
	return &NodeGroup{
		nodes: nodes,
	}
}

func (group *NodeGroup) AddNode(node ...Node) {
	if group == nil {
		return
	}
	group.mux.Lock()
	defer group.mux.Unlock()

	group.nodes = append(group.nodes, node...)
}

func (group *NodeGroup) SetNodes(nodes ...Node) []Node {
	if group == nil {
		return nil
	}

	group.mux.Lock()
	defer group.mux.Unlock()

	old := group.nodes
	group.nodes = nodes
	return old
}

func (group *NodeGroup) SetSelector(selector NodeSelector, opts ...SelectOption) {
	if group == nil {
		return
	}
	group.mux.Lock()
	defer group.mux.Unlock()

	group.selector = selector
	group.selectorOptions = opts
}

func (group *NodeGroup) Nodes() []Node {
	if group == nil {
		return nil
	}

	group.mux.RLock()
	defer group.mux.RUnlock()

	return group.nodes
}

func (group *NodeGroup) GetNode(i int) Node {
	group.mux.RLock()
	defer group.mux.RUnlock()

	if i < 0 || group == nil || len(group.nodes) <= i {
		return Node{}
	}
	return group.nodes[i]
}

func (group *NodeGroup) Next() (node Node, err error) {
	if group == nil {
		return
	}

	group.mux.RLock()
	defer group.mux.RUnlock()

	selector := group.selector
	if selector == nil {
		selector = &defaultSelector{}
	}

	node, err = selector.Select(group.nodes, group.selectorOptions...)
	if err != nil {
		return
	}

	return
}
