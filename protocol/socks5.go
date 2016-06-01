package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	cfg "github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
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
	version = 0
	nmethod = 1

	socksV5         = 5
	socksCmdConnect = 1

	domainLen = 4
	ipv4      = 1
	ipv6      = 4
	domain    = 3

	ipv4Len    = 3 + 1 + net.IPv4len + 2 //3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	ipv6Len    = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	domainTLen = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
)

//Tunnel ...
type Tunnel interface {
	Handle()
}

type receiver struct {
	config   *cfg.LocalConfig
	listener net.Listener
}

//NewTunnel ...
func NewTunnel(config *cfg.LocalConfig, listener net.Listener) Tunnel {
	return &receiver{config, listener}
}

func (receiver *receiver) handshake(conn net.Conn) error {
	//the largest buffer size is 258
	buf := make([]byte, 258)
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, nmethod+1); err != nil {
		logger.Errorf("Socks5--->read data error %s\n", err)
		return err
	}
	if buf[version] != socksV5 {
		logger.Errorf("Socks5--->error version socks %v\n", buf[version])
		return errSocks
	}
	nmethod := int(buf[nmethod])
	msgLen := nmethod + 2
	if n == msgLen {
		//TODO
	} else if msgLen < n {
		return errAuth
	} else {
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			logger.Errorf("Socks5--->read data error,cannot finish handshake %s\n", err)
			return err
		}
	}
	_, err = conn.Write([]byte{socksV5, 0})
	return err
}

func (receiver *receiver) request(conn net.Conn) ([]byte, string, bool, error) {
	buf := make([]byte, 263)
	//conn.SetReadDeadline(time.Now().Add(l.timeout))
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, domainLen+1); err != nil {
		logger.Errorf("Socks5--->read data from client error %s\n", err)
		return nil, "", false, err
	}
	if buf[version] != socksV5 {
		return nil, "", false, errSocks
	}
	//cmd
	if buf[1] != socksCmdConnect {
		logger.Errorf("Socks5--->error socks cmd value is %v\n", buf[1])
		return nil, "", false, errCmd
	}
	var hstLen int
	//host item like ipv4,ipv6,domian and so on
	switch buf[3] {
	case ipv4:
		hstLen = ipv4Len
	case ipv6:
		hstLen = ipv6Len
	case domain:
		hstLen = int(buf[domainLen]) + domainTLen
	default:
		return nil, "", false, errAddr
	}
	if n < hstLen {
		if _, err := io.ReadFull(conn, buf[n:hstLen]); err != nil {
			logger.Errorf("Socks5--->read data error %s\n", err)
			return nil, "", false, err
		}
	} else if n > hstLen {
		logger.Errorf("Socks5--->some error")
		return nil, "", false, errors.New("error socks data export")
	}
	//id type is 3
	//ip start idex
	ipIndex := 4
	domian := false
	rawAddr := buf[3:hstLen]
	var hst string
	switch buf[3] {
	case ipv4:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv4len]).String()
	case ipv6:
		hst = net.IP(buf[ipIndex : ipIndex+net.IPv6len]).String()
	case domain:
		hst = string(buf[5 : 5+buf[domainLen]])
		domian = true
	}
	port := binary.BigEndian.Uint16(buf[hstLen-2 : hstLen])
	host := net.JoinHostPort(hst, strconv.Itoa(int(port)))
	return rawAddr, host, domian, nil
}

func (receiver *receiver) handleConnection(conn net.Conn) {
	var err error
	if err = receiver.handshake(conn); err != nil {
		logger.Errorf("Socks5--->handshake error %s\n", err)
		return
	}

	//set default timeout
	cfg.SetTimeout(conn.SetReadDeadline, receiver.config.Timeout)
	//conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))

	rawAddr, host, domian, err := receiver.request(conn)
	if err != nil {
		logger.Errorf("Socks5--->get host failed %s\n", err)
		return
	}
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		logger.Errorf("Socks5--->error send data to client %s\n", err)
		return
	}
	//need connect to remote server or not
	if domian && !cfg.IsInWhiteList(strings.Split(host, ":")[0]) {
		result := cfg.ParserDomain(strings.Split(host, ":")[0])
		if result {
			handleChina(conn, host)
			return
		}
	} else if !domian {
		result := cfg.ParserIP(strings.Split(host, ":")[0])
		if result {
			handleChina(conn, host)
			return
		}
	}
	ci, flag, err := client.NewRemoteServer(receiver.config).ChooseServer()
	if err != nil {
		logger.Errorf("Socks5--->connect to server failed %s", err)
		return
	}
	if flag {
		cli := ci.(*client.SSLClient)
		cfg.SetTimeout(cli.Conn.SetReadDeadline, receiver.config.Timeout)
		defer func() {
			cli.Conn.Close()
			conn.Close()
		}()
		if _, err = cli.Conn.Write(rawAddr); err != nil {
			logger.Errorf("Socks5--->handle error message when write data %s \n", err)
			return
		}
		pipe(&cli.Conn, conn)
		return
	}
	cli := ci.(*client.Client)
	cfg.SetTimeout(cli.Conn.SetReadDeadline, receiver.config.Timeout)
	//cli.Conn.SetReadDeadline(time.Now().Add(time.Duration(s.config.Timeout) * time.Second))
	defer func() {
		cli.Conn.Close()
		conn.Close()
	}()
	if _, err = cli.Conn.Write(rawAddr); err != nil {
		logger.Errorf("Socks5--->handle error message when write data %s \n", err)
		return
	}
	pipe(cli.Conn, conn)
}

//Handle ...
func (receiver *receiver) Handle() {
	for {
		conn, err := receiver.listener.Accept()
		if err != nil {
			logger.Errorf("Socks5--->handle connection error %s\n", err)
			continue
		}
		go receiver.handleConnection(conn)
	}
}
