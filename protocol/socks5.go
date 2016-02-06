package protocol

import (
	"encoding/binary"
	"errors"
	cfg "github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"io"
	"net"
	"strconv"
	"strings"
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

	DOMAIN_LEN = 4
	IPV4       = 1
	IPV6       = 4
	DOMAIN     = 3

	IPV4_LEN    = 3 + 1 + net.IPv4len + 2 //3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	IPV6_LEN    = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	DOMAIN_TLEN = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
)

type Socks5Tunnel struct {
	config   *cfg.FileConfig
	listener net.Listener
}

func NewSocks5Tunnel(config *cfg.FileConfig, listener net.Listener) *Socks5Tunnel {
	return &Socks5Tunnel{config, listener}
}

func (l *Socks5Tunnel) handshake(conn net.Conn) error {
	//the largest buffer size is 258
	buf := make([]byte, 258)
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, NMETHOD+1); err != nil {
		logger.Errorf("Socks5--->read data error %s\n", err)
		return err
	}
	if buf[VERSION] != SOCKS_V5 {
		logger.Errorf("Socks5--->error version socks %v\n", buf[VERSION])
		return errSocks
	}
	nmethod := int(buf[NMETHOD])
	msgLen := nmethod + 2
	if n == msgLen {
		logger.Error("handshake done,ok")
	} else if msgLen < n {
		return errAuth
	} else {
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			logger.Errorf("Socks5--->read data error,cannot finish handshake %s\n", err)
			return err
		}
	}
	_, err = conn.Write([]byte{SOCKS_V5, 0})
	return err
}

func (l *Socks5Tunnel) request(conn net.Conn) ([]byte, string, bool, error) {
	buf := make([]byte, 263)
	//conn.SetReadDeadline(time.Now().Add(l.timeout))
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, DOMAIN_LEN+1); err != nil {
		logger.Errorf("Socks5--->read data from client error %s\n", err)
		return nil, "", false, err
	}
	if buf[VERSION] != SOCKS_V5 {
		return nil, "", false, errSocks
	}
	//cmd
	if buf[1] != SOCKS_CMD_CONNECT {
		logger.Errorf("Socks5--->error socks cmd value is %v\n", buf[1])
		return nil, "", false, errCmd
	}
	var hstLen int
	//host item like ipv4,ipv6,domain and so on
	switch buf[3] {
	case IPV4:
		hstLen = IPV4_LEN
	case IPV6:
		hstLen = IPV6_LEN
	case DOMAIN:
		hstLen = int(buf[DOMAIN_LEN]) + DOMAIN_TLEN
	default:
		return nil, "", false, errAddr
	}
	if n < hstLen {
		if _, err := io.ReadFull(conn, buf[n:hstLen]); err != nil {
			logger.Errorf("Socks5--->read data error %s\n", err)
			return nil, "", false, err
		}
	} else if n > hstLen {
		logger.Errorf("Socks5--->fuck you ,some error")
		return nil, "", false, errors.New("error socks data export")
	}
	//id type is 3
	//ip start idex
	ipIndex := 4
	domain := false
	rawAddr := buf[3:hstLen]
	var hst string
	switch buf[3] {
	case IPV4:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv4len]).String()
	case IPV6:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv6len]).String()
	case DOMAIN:
		hst = string(buf[5 : 5+buf[DOMAIN_LEN]])
		domain = true
	}
	port := binary.BigEndian.Uint16(buf[hstLen-2 : hstLen])
	host := net.JoinHostPort(hst, strconv.Itoa(int(port)))
	return rawAddr, host, domain, nil
}

func (s *Socks5Tunnel) handleConnection(conn net.Conn) {
	var err error
	if err = s.handshake(conn); err != nil {
		logger.Errorf("Socks5--->handshake error %s\n", err)
		return
	}

	//set default timeout
	cfg.SetTimeout(conn.SetReadDeadline, s.config.Timeout)
	//conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))

	rawAddr, host, domain, err := s.request(conn)
	if err != nil {
		logger.Errorf("Socks5--->get host failed %s\n", err)
		return
	}
	logger.Errorf("find byte %v bytestr %s\n", rawAddr, string(rawAddr))
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		logger.Errorf("Socks5--->error send data to client %s\n", err)
		return
	}
	//need connect to remote server or not
	if domain && !cfg.IsInWhiteList(strings.Split(host, ":")[0]) {
		result := cfg.ParserDomain(strings.Split(host, ":")[0])
		//if china
		if result {
			handleChina(conn, host)
			return
		}
	} else if !domain {
		result := cfg.ParserIP(strings.Split(host, ":")[0])
		if result {
			handleChina(conn, host)
			return
		}
	}
	ci, flag, err := client.NewSP(s.config).ChooseServer()
	if err != nil {
		logger.Errorf("Socks5--->connect to server failed %s", err)
		return
	}
	if flag {
		cli := ci.(*client.SSLClient)
		cfg.SetTimeout(cli.Conn.SetReadDeadline, s.config.Timeout)
		//cli.Conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
		defer func() {
			cli.Conn.Close()
			conn.Close()
			logger.Errorf("Socks5--->local proxy closed...")
		}()
		if _, err = cli.Conn.Write(rawAddr); err != nil {
			logger.Errorf("Socks5--->handle error message when write data %s \n", err)
			return
		}
		pipe(&cli.Conn, conn)
		return
	}
	cli := ci.(*client.Client)
	cfg.SetTimeout(cli.Conn.SetReadDeadline, s.config.Timeout)
	//cli.Conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
	defer func() {
		cli.Conn.Close()
		conn.Close()
		logger.Errorf("Socks5--->local proxy closed...")
	}()
	if _, err = cli.Conn.Write(rawAddr); err != nil {
		logger.Errorf("Socks5--->handle error message when write data %s \n", err)
		return
	}
	pipe(cli.Conn, conn)
}

func (s *Socks5Tunnel) Handle() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			logger.Errorf("Socks5--->handle connection error %s\n", err)
			continue
		}
		go s.handleConnection(conn)
	}
}
