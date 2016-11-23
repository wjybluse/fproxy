package main

import (
	"net"
	"strconv"

	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/server"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("server")

func main() {
	var conf config.ServerConf
	config.Create("./config/server.json", &conf)
	go func() {
		listener, err := net.Listen("tcp", conf.Host+":"+strconv.Itoa(conf.Port))
		if err != nil {
			logger.Errorf("[SERVER]:error listen in port %s:%d \n", conf.Host, conf.Port)
			panic("deam!!!!!!!")
		}
		s := server.SocksServer(&listener, &conf)
		s.Handle()
	}()
	addr, err := net.ResolveUDPAddr("udp", conf.Host+":"+strconv.Itoa(conf.Port))
	if err != nil {
		logger.Errorf("[SERVER]:error create udp listener in port %s:%d \n", conf.Host, conf.Port)
		panic("udp error")
	}
	ul, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Errorf("[SERVER]:error create udp listener in port %s:%d \n", conf.Host, conf.Port)
		panic("udp error")
	}
	defer ul.Close()
	s := server.NewUDPServer(ul, &conf)
	s.Handle()
}
