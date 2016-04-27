package local

import (
	"net"
	"strconv"
	"time"

	cf "github.com/elians/fproxy/config"
	"github.com/elians/fproxy/protocol"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("local")

type local struct {
	listener net.Listener
	timeout  time.Duration
}

func (l *local) close() {
	l.listener.Close()
}

func newLoalServer(cfg *cf.LocalConfig) *local {
	h := cfg.Local + ":" + strconv.Itoa(cfg.LocalPort)
	listener, err := net.Listen("tcp", h)
	if err != nil {
		logger.Errorf("cannot listen the port %s\n", err)
		return nil
	}
	return &local{listener, 100}
}

//Server ...
func Server(cfg *cf.LocalConfig) {
	server := newLoalServer(cfg)
	if server == nil {
		logger.Errorf("cannot create server")
		return
	}
	if cfg.Protcol == "http" {
		protocol.NewHTTPTunnel(server.listener, cfg).Handle()
		return
	}
	protocol.NewTunnel(cfg, server.listener).Handle()
}
