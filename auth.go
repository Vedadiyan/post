package post

import (
	"sync"
)

type (
	Authenticator interface {
		Authenticate(user, password string) bool
	}
	LocalAuthenticator struct {
		kvs     map[string]string
		stopped chan struct{}
		mux     sync.RWMutex
	}
)

func NewLocalAuthenticator(kvs map[string]string) *LocalAuthenticator {
	return &LocalAuthenticator{
		kvs:     kvs,
		stopped: make(chan struct{}),
	}
}

func (au *LocalAuthenticator) Authenticate(user, password string) bool {
	if au == nil {
		return true
	}

	au.mux.RLock()
	defer au.mux.RUnlock()

	if len(au.kvs) == 0 {
		return true
	}

	v, ok := au.kvs[user]
	return ok && (v == "" || password == v)
}
