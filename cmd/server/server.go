package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/server"
	"github.com/op/go-logging"
	"net"
	"strconv"
)
var logger = logging.MustGetLogger("server")

func main() {
	var conf config.ServerConf
	config.Create("./config/server.json", &conf)
  listener,err := net.Listen("tcp", conf.Host+":"+strconv.Itoa(conf.Port))
  if err!=nil{
		  logger.Errorf("[SERVER]:error listen in port %s:%d \n", conf.Host,conf.Port)
			panic("deam!!!!!!!")
		}
	s :=server.SocksServer(&listener, &conf)
	s.Handle()
}
