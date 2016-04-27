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

func (receiver *socksReceiver) handleConnection(conn net.Conn) {
	data, host, err := receiver.request(conn)
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
		//fixe bug when cli is nil
		if cli != nil {
			cli.Close()
		}
		conn.Close()
	}()
	if _, err := cli.Conn.Write(data); err != nil {
		logger.Error("Server:----->write data error")
		return
	}

	c.SetTimeout(cli.Conn.SetReadDeadline, receiver.cfg.Timeout)
	c.SetTimeout(conn.SetReadDeadline, receiver.cfg.Timeout)
	//for comment
	go io.Copy(cli.Conn, conn)
	io.Copy(conn, cli.Conn)

}

func (receiver *socksReceiver) request(conn net.Conn) ([]byte, string, error) {
	buf := make([]byte, 260)
	//conn.SetReadDeadline(time.Now().Add(l.timeout))
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, domainLen+1); err != nil {
		logger.Errorf("Server:---->read data from client error %s\n", err)
		return nil, "", err
	}
	var hstLen int
	//host item like ipv4,ipv6,domain and so on
	switch buf[0] {
	case ipv4:
		hstLen = ipv4Len
	case ipv6:
		hstLen = ipv6Len
	case domain:
		hstLen = int(buf[domainLen]) + domainTLen
	default:
		return nil, "", errAddr
	}
	var rawAddr []byte
	if n < hstLen {
		if _, err := io.ReadFull(conn, buf[n:hstLen]); err != nil {
			logger.Errorf("Server:---->read data error %s\n", err)
			return nil, "", err
		}
	} else if n > hstLen {
		logger.Error("Server:---->fuck you ,some error")
		rawAddr = buf[hstLen:n]
	}
	//id type is 3
	//ip start idex
	ipIndex := 1
	var hst string
	switch buf[0] {
	case ipv4:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv4len]).String()
	case ipv6:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv6len]).String()
	case domain:
		hst = string(buf[2 : 2+buf[domainLen]])
	}
	port := binary.BigEndian.Uint16(buf[hstLen-2 : hstLen])
	host := net.JoinHostPort(hst, strconv.Itoa(int(port)))
	return rawAddr, host, nil
}

func (receiver *socksReceiver) Handle() {
	for {
		conn, err := receiver.listener.Accept()
		if err != nil {
			logger.Errorf("Server--->socks5 error %s", err)
			continue
		}
		go receiver.handleConnection(conn)
	}

}

//NewSocksTunnel ...
func NewSocksTunnel(listener net.Listener, cfg *c.RemoteConfig) protocol.Tunnel {
	return &socksReceiver{listener, cfg}
}
