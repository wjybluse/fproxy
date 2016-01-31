package server

import (
	"crypto/tls"
	c "github.com/elians/fproxy/config"
	"github.com/op/go-logging"
	"net"
	"strconv"
)

var logger = logging.MustGetLogger("server")

type PServer struct {
	listener net.Listener
}

func newServer(vpsConfig *c.RemoteVPS) *PServer {
	host := vpsConfig.Host + ":" + strconv.Itoa(vpsConfig.Port)
	ts, err := tls.Listen("tcp", host, c.NewSSLConfig())
	if err != nil {
		logger.Errorf("create server failed %s", err)
		return nil
	}
	return &PServer{ts}
}

func CreateServer(cfg *c.RemoteVPS) {
	server := newServer(cfg)
	if server == nil {
		logger.Errorf("Server--->cannot create server")
		return
	}
	s := NewSocks5(server.listener, cfg)
	s.Handle()
}
