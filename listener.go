package post

type router struct {
	node    Node
	server  *Server
	handler Handler
}

func (r *router) Serve() error {
	return r.server.Serve(r.handler)
}

func (r *router) Close() error {
	if r == nil || r.server == nil {
		return nil
	}
	return r.server.Close()
}

func ListenAndServe(socks5Address string, httpAddress string) error {
	listener, err := TCPListener(socks5Address)
	if err != nil {
		return err
	}
	node, err := ParseNode(httpAddress)
	if err != nil {
		return err
	}
	routers := []router{
		{node: node,
			server:  &Server{Listener: listener},
			handler: SOCKS5Handler(),
		},
	}
	for i := range routers {
		go routers[i].Serve()
	}
	return nil
}
