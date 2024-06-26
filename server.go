package post

import (
	"io"
	"net"
	"time"
)

type (
	Accepter interface {
		Accept() (net.Conn, error)
	}
	Server struct {
		Listener Listener
		Handler  Handler
		options  *ServerOptions
	}
	ServerOptions struct {
	}
	ServerOption func(opts *ServerOptions)
	Listener     interface {
		net.Listener
	}
)

func (s *Server) Init(opts ...ServerOption) {
	if s.options == nil {
		s.options = &ServerOptions{}
	}
	for _, opt := range opts {
		opt(s.options)
	}
}

func (s *Server) Addr() net.Addr {
	return s.Listener.Addr()
}

func (s *Server) Close() error {
	return s.Listener.Close()
}

func (s *Server) Serve(h Handler, opts ...ServerOption) error {
	s.Init(opts...)

	if s.Listener == nil {
		ln, err := TCPListener("")
		if err != nil {
			return err
		}
		s.Listener = ln
	}

	if h == nil {
		h = s.Handler
	}
	if h == nil {
		h = HTTPHandler()
	}

	l := s.Listener
	var tempDelay time.Duration
	for {
		conn, e := l.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0

		go h.Handle(conn)
	}
}

func (s *Server) Run() error {
	return s.Serve(s.Handler)
}

func transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		errc <- copyBuffer(rw1, rw2)
	}()

	go func() {
		errc <- copyBuffer(rw2, rw1)
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}

	return nil
}

func copyBuffer(dst io.Writer, src io.Reader) error {
	_buf := lPool.Get().(*[]byte)
	buf := *_buf
	defer lPool.Put(&buf)

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}
