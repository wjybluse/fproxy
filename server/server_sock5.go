package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	c "github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"github.com/elians/fproxy/protocol"
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

type socksReceiver struct {
	listener net.Listener
	cfg      *c.RemoteConfig
}

func (sr *socksReceiver) handleConnection(conn net.Conn) {
	data, host, err := handleRequest(conn)
	if err != nil {
		logger.Errorf("Server:---->cannot find host %s\n", err)
		return
	}
	cli := client.NewClient(host)
	if cli == nil {
		logger.Error("handle connection error,cannot create client.")
		return
	}
	defer func() {
		// close if exit
		cli.Close()
		conn.Close()
	}()
	if _, err := cli.Conn.Write(data); err != nil {
		logger.Errorf("[ERROR]:write data error %s\n", err)
		return
	}

	c.SetTimeout(cli.Conn.SetReadDeadline, sr.cfg.Timeout)
	c.SetTimeout(conn.SetReadDeadline, sr.cfg.Timeout)
	//for comment
	go io.Copy(cli.Conn, conn)
	io.Copy(conn, cli.Conn)

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
		conn, err := sr.listener.Accept()
		if err != nil {
			logger.Errorf("[ERROR]:create connection with client error %s", err)
			continue
		}
		go sr.handleConnection(conn)
	}

}

//NewSocksTunnel ...
func NewSocksTunnel(listener net.Listener, cfg *c.RemoteConfig) protocol.Tunnel {
	return &socksReceiver{listener, cfg}
}
