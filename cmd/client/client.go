package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/protocol"
	"github.com/op/go-logging"
	"net"
	"strconv"
)
var logger = logging.MustGetLogger("client")

func main() {
	var conf config.Conf
	config.Create("./config/conf.json", &conf)
	listener,err:=net.Listen("tcp", conf.Local+":"+strconv.Itoa(conf.LocalPort))
	if err!=nil{
		logger.Errorf("[CLIENT]:cannot create local server %s \n", err)
		panic("error create local server")
	}
	if conf.Protcol == "http"{
		s := protocol.HTTPWraper(&listener, &conf)
		s.Handle()
	}else{
		s := protocol.Socks5Wrap(&listener,&conf)
		s.Handle()
	}
}
