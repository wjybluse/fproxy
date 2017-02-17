package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/elians/fproxy/config"
	c "github.com/elians/fproxy/conn"
	"github.com/elians/fproxy/protocol"
	"github.com/op/go-logging"
)

var (
	errMethod = errors.New("Error method")
	errAuth   = errors.New("socks auth error")
	errSocks  = errors.New("error socks version")
	errCmd    = errors.New("error socks cmd")
	errAddr   = errors.New("error ip address")
)

const (
	version = 0
	nmethod = 1

	socksV5         = 5
	socksCmdConnect = 1

	domainLen = 1
	ipv4      = 1
	ipv6      = 4
	domain    = 3

	ipv4Len    = 1 + net.IPv4len + 2 //3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	ipv6Len    = 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	domainTLen = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
)

var logger = logging.MustGetLogger("server")

type socksReceiver struct {
	listener *net.Listener
	cfg      *config.ServerConf
}

func (sr *socksReceiver) handleConnection(conn net.Conn) {
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

func handleRequest(conn net.Conn) (rawAddr []byte, host string, err error) {
	//max length
	buf := make([]byte, 260)
	//declare read bit
	var n int
	if n, err = io.ReadAtLeast(conn, buf, domainLen+1); err != nil {
		logger.Errorf("[ERROR]:read data from client error %s\n", err)
		return
	}
	hstlen, maxlen := getHostTypeAndLen(buf)
	if hstlen > n {
		if _, err = io.ReadFull(conn, buf[n:hstlen]); err != nil {
			logger.Errorf("[ERROR]:Read full data from client error %s\n", err)
			return
		}
	}
	rawAddr = buf[hstlen:n]
	port := binary.BigEndian.Uint16(buf[hstlen-2 : hstlen])
	if buf[0] == domain {
		host = net.JoinHostPort(string(buf[2:maxlen]), strconv.Itoa(int(port)))
		return
	}
	host = net.JoinHostPort(string(buf[1:1+maxlen]), strconv.Itoa(int(port)))
	return
}

func getHostTypeAndLen(buf []byte) (int, int) {
	hostType := buf[0]
	if hostType == ipv4 {
		return ipv4Len, net.IPv4len
	}
	if hostType == ipv6 {
		return ipv6Len, net.IPv6len
	}
	// default is domain
	return int(buf[domainLen]) + domainTLen, 2 + int(buf[domainLen])
}

func (sr *socksReceiver) Handle() {
	for {
		conn, err := (*sr.listener).Accept()
		if err != nil {
			logger.Errorf("[ERROR]:create connection with client error %s", err)
			continue
		}
		go sr.handleConnection(conn)
	}

}

//SocksServer ...
func SocksServer(listener *net.Listener, sf *config.ServerConf) protocol.GreenTunnel {
	return &socksReceiver{listener, sf}
}
