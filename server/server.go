package server

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	c "github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	errMethod = errors.New("Error method")
	errAuth   = errors.New("socks auth error")
	errSocks  = errors.New("error socks version")
	errCmd    = errors.New("error socks cmd")
	errAddr   = errors.New("error ip address")
)
var vpsConfig c.RemoteVPS

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

type PServer struct {
	listener net.Listener
}

func newServer() *PServer {
	host := vpsConfig.Host + ":" + strconv.Itoa(vpsConfig.Port)
	ts, err := tls.Listen("tcp", host, c.NewSSLConfig())
	if err != nil {
		fmt.Printf("create server failed %s", err)
		return nil
	}
	return &PServer{ts}
}
func (p *PServer) handle() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			fmt.Printf("Server:---->failed ,skip all eror %s\n", err)
			continue
		}
		go p.handleConnection(conn)
	}
}

func (p *PServer) handleConnection(conn net.Conn) {
	fmt.Println("Server:---->recevie data from local proxy")
	data, host, err := p.request(conn)
	if err != nil {
		fmt.Printf("Server:---->cannot find host %s\n", err)
		return
	}
	fmt.Printf("Server:---->find remote server %s\n", host)
	cli := client.NewClient(host)
	defer func() {
		fmt.Println("server closed")
		cli.Close()
		conn.Close()
	}()
	if _, err := cli.Conn.Write(data); err != nil {
		fmt.Println("Server:----->write data error")
		return
	}
	fmt.Println("Server:---->copy data begin...")
	cli.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	go c.CopyWithDecompressed(cli.Conn, conn)
	c.CopyWithCompressed(conn, cli.Conn)
	//for comment
	//go io.Copy(cli.Conn, conn)
	//io.Copy(conn, cli.Conn)

}

func (p *PServer) request(conn net.Conn) ([]byte, string, error) {
	buf := make([]byte, 260)
	//conn.SetReadDeadline(time.Now().Add(l.timeout))
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, DOMAIN_LEN+1); err != nil {
		fmt.Printf("Server:---->read data from client error %s\n", err)
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
			fmt.Printf("Server:---->read data error %s\n", err)
			return nil, "", err
		}
	} else if n > hstLen {
		fmt.Println("Server:---->fuck you ,some error")
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

func CreateServer(vconfig *c.RemoteVPS) {
	vpsConfig = *vconfig
	s := newServer()
	if s == nil {
		fmt.Printf("Server:---->cannot create server..%s", "hahha")
		os.Exit(1)
	}
	s.handle()
}
