package server

import (
	"encoding/binary"
	"errors"
	c "github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"io"
	"net"
	"strconv"
)

var (
	errMethod = errors.New("Error method")
	errAuth   = errors.New("socks auth error")
	errSocks  = errors.New("error socks version")
	errCmd    = errors.New("error socks cmd")
	errAddr   = errors.New("error ip address")
)

const (
	//for handshake
	VERSION = 0
	NMETHOD = 1

	SOCKS_V5          = 5
	SOCKS_CMD_CONNECT = 1

	DOMAIN_LEN = 1
	IPV4       = 1
	IPV6       = 4
	DOMAIN     = 3

	IPV4_LEN    = 1 + net.IPv4len + 2 //3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	IPV6_LEN    = 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	DOMAIN_TLEN = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
)

type ServerSock5 struct {
	listener net.Listener
	cfg      *c.RemoteVPS
}

func (s *ServerSock5) handleConnection(conn net.Conn) {
	logger.Error("Server:---->recevie data from local proxy")
	data, host, err := s.request(conn)
	if err != nil {
		logger.Errorf("Server:---->cannot find host %s\n", err)
		return
	}
	logger.Errorf("Server:---->find remote server %s\n", host)
	cli := client.NewClient(host)
	defer func() {
		cli.Close()
		conn.Close()
	}()
	if _, err := cli.Conn.Write(data); err != nil {
		logger.Error("Server:----->write data error")
		return
	}
	logger.Error("Server:---->copy data begin...")

	c.SetTimeout(cli.Conn.SetReadDeadline, s.cfg.Timeout)
	c.SetTimeout(conn.SetReadDeadline, s.cfg.Timeout)
	//for comment
	go io.Copy(cli.Conn, conn)
	io.Copy(conn, cli.Conn)

}

func (s *ServerSock5) request(conn net.Conn) ([]byte, string, error) {
	buf := make([]byte, 260)
	//conn.SetReadDeadline(time.Now().Add(l.timeout))
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, DOMAIN_LEN+1); err != nil {
		logger.Errorf("Server:---->read data from client error %s\n", err)
		return nil, "", err
	}
	var hstLen int
	//host item like ipv4,ipv6,domain and so on
	switch buf[0] {
	case IPV4:
		hstLen = IPV4_LEN
	case IPV6:
		hstLen = IPV6_LEN
	case DOMAIN:
		hstLen = int(buf[DOMAIN_LEN]) + DOMAIN_TLEN
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
	case IPV4:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv4len]).String()
	case IPV6:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv6len]).String()
	case DOMAIN:
		hst = string(buf[2 : 2+buf[DOMAIN_LEN]])
	}
	port := binary.BigEndian.Uint16(buf[hstLen-2 : hstLen])
	host := net.JoinHostPort(hst, strconv.Itoa(int(port)))
	return rawAddr, host, nil
}

func (s *ServerSock5) Handle() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			logger.Errorf("Server--->socks5 error %s", err)
			continue
		}
		go s.handleConnection(conn)
	}

}

func NewSocks5(listener net.Listener, cfg *c.RemoteVPS) *ServerSock5 {
	return &ServerSock5{listener, cfg}
}
