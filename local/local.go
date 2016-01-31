package local

import (
	cf "github.com/elians/fproxy/config"
	"github.com/elians/fproxy/protocol"
	"github.com/op/go-logging"
	"net"
	"strconv"
	"time"
)

var logger = logging.MustGetLogger("local")

type LocalServer struct {
	listener net.Listener
	timeout  time.Duration
}

func (l *LocalServer) close() {
	l.listener.Close()
}

func newLoalServer(cfg *cf.FileConfig) *LocalServer {
	h := cfg.Local + ":" + strconv.Itoa(cfg.LocalPort)
	listener, err := net.Listen("tcp", h)
	if err != nil {
		logger.Errorf("cannot listen the port %s\n", err)
		return nil
	}
	return &LocalServer{listener, 100}
}

func CreateLocalServer(cfg *cf.FileConfig) {
	server := newLoalServer(cfg)
	if server == nil {
		logger.Errorf("cannot create server")
		return
	}
	if cfg.Protcol == "http" {
		protocol.NewHPProxy(server.listener, cfg).Handle()
		return
	}
	protocol.NewSocks5Tunnel(cfg, server.listener).Handle()
}
