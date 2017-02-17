package server

import (
	"io"
	"net"

	"github.com/elians/fproxy/config"
	c "github.com/elians/fproxy/conn"
	"github.com/elians/fproxy/protocol"
)

type udpRecevier struct {
	conn net.Conn
	cfg  *config.ServerConf
}

func (sr *udpRecevier) handleConnection(conn net.Conn) {
	data, host, err := handleRequest(conn)
	if err != nil {
		logger.Errorf("[SERVER]:cannot find host %s\n", err)
		return
	}
	defer conn.Close()
	connector, err := c.NewConnector(host, false)
	if err != nil {
		logger.Errorf("[SERVER]:create client failed %s \n", err)
		return
	}
	defer connector.Close()
	con, _ := connector.Connect()
	if _, err := con.Write(data); err != nil {
		logger.Errorf("[ERROR]:write data error %s\n", err)
		return
	}

	//for comment
	go io.Copy(con, conn)
	io.Copy(conn, con)

}

func (sr *udpRecevier) Handle() {
	for {
		sr.handleConnection(sr.conn)
	}
}

//NewUDPServer ...
func NewUDPServer(conn net.Conn, sf *config.ServerConf) protocol.GreenTunnel {
	return &udpRecevier{
		conn: conn,
		cfg:  sf,
	}
}
