package server

import (
	"github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"io"
	"net"
	"net/http"
)

type ServerHttps struct {
	listener net.Listener
	cfg      *config.RemoteVPS
}

func NewServerHttps(listener net.Listener, cfg *config.RemoteVPS) *ServerHttps {
	return &ServerHttps{listener, cfg}
}

func (s *ServerHttps) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	hijack := resp.(http.Hijacker)
	cli, _, err := hijack.Hijack()
	if err != nil {
		logger.Errorf("Server------>handle error message %s\n", err)
		return
	}
	defer func() {
		cli.Close()
	}()
	hst := req.URL.Host
	c := client.NewClient(hst)
	if c == nil {
		logger.Error("Server------>create client failed")
		return
	}
	defer func() {
		c.Close()
		cli.Close()
	}()
	go io.Copy(c.Conn, cli)
	io.Copy(cli, c.Conn)
}

func (s *ServerHttps) Handle() {
	err := http.Serve(s.listener, s)
	if err != nil {
		logger.Errorf("Server----->handle error message %s\n", err)
		return
	}
	logger.Error("Server------>start server......")
}
