package post

import (
	"net"
	"sync"
)

type (
	Host struct {
		IP       net.IP
		Hostname string
		Aliases  []string
	}

	Hosts struct {
		hosts []Host
		mux   sync.RWMutex
	}
)

func NewHost(ip net.IP, hostname string, aliases ...string) Host {
	return Host{
		IP:       ip,
		Hostname: hostname,
		Aliases:  aliases,
	}
}

func (h *Hosts) Lookup(host string) (ip net.IP) {
	if h == nil || host == "" {
		return
	}

	h.mux.RLock()
	defer h.mux.RUnlock()

	for _, h := range h.hosts {
		if h.Hostname == host {
			ip = h.IP
			break
		}
		for _, alias := range h.Aliases {
			if alias == host {
				ip = h.IP
				break
			}
		}
	}
	return
}
