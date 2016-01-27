package local

import (
	"fmt"
	cf "github.com/elians/fproxy/config"
	"github.com/elians/fproxy/protcol"
	"net"
	"strconv"
	"time"
)

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
		fmt.Printf("cannot listen the port %s\n", err)
		return nil
	}
	return &LocalServer{listener, 100}
}

func CreateLocalServer(cfg *cf.FileConfig) {
	server := newLoalServer(cfg)
	if server == nil {
		fmt.Println("cannot create server")
		return
	}
	if cfg.Protcol == "http" {
		fmt.Printf("handle http listener")
		protcol.NewHPProxy(server.listener, cfg).Handle()
		return
	}
	protcol.NewSocks5Tunnel(cfg, server.listener)
}
