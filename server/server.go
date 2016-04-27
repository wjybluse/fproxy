package server

import (
	"crypto/tls"
	"net"
	"strconv"

	c "github.com/elians/fproxy/config"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("server")

type pserver struct {
	listener net.Listener
}

func newServer(vpsConfig *c.RemoteConfig) *pserver {
	host := vpsConfig.Host + ":" + strconv.Itoa(vpsConfig.Port)
	ts, err := tls.Listen("tcp", host, c.NewSSLConfig())
	if err != nil {
		logger.Errorf("create server failed %s", err)
		return nil
	}
	return &pserver{ts}
}

//Server ...
func Server(cfg *c.RemoteConfig) {
	server := newServer(cfg)
	if server == nil {
		logger.Errorf("Server--->cannot create server")
		return
	}
	s := NewSocksTunnel(server.listener, cfg)
	s.Handle()
}
