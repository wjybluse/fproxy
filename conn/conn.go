package conn

import (
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	p "github.com/elians/fproxy/config"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("conn")

//RemoteServer ...
type RemoteServer struct {
	config *p.LocalConfig
}

//Client ...
type Client struct {
	Conn net.Conn
}

//SSLClient ...
type SSLClient struct {
	Conn tls.Conn
}

//Close ...
func (c *Client) Close() {
	c.Conn.Close()
}

//Close ...
func (s *SSLClient) Close() {
	s.Conn.Close()
}

//NewClient ...
func NewClient(host string) *Client {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		logger.Errorf("Error:--->cannnot create client %s\n", err)
		return nil
	}
	return &Client{conn}
}

//NewSSLClient ...
func NewSSLClient(host string) *SSLClient {
	conn, err := tls.Dial("tcp", host, p.NewSSLConfig())
	if err != nil {
		logger.Errorf("Error:--->cannnot create client %s\n", err)
		return nil
	}
	return &SSLClient{*conn}
}

func (p *RemoteServer) ChooseServer() (interface{}, bool, error) {
	if len(p.config.Servers) <= 0 {
		return nil, false, errors.New("invalid servers")
	}
	for _, server := range p.config.Servers {
		if server.SSL {
			cli := NewSSLClient(net.JoinHostPort(server.Host, strconv.Itoa(server.Port)))
			if cli == nil {
				logger.Errorf("cannot connect to server %v via ssl \n", server)
				continue
			}
			cli.Conn.SetReadDeadline(time.Now().Add(time.Duration(server.Timeout) * time.Second))
			return cli, true, nil
		}
		cli := NewClient(net.JoinHostPort(server.Host, strconv.Itoa(server.Port)))
		if cli == nil {
			logger.Errorf("cannot connect to server %v \n", server)
			continue
		}
		cli.Conn.SetReadDeadline(time.Now().Add(time.Duration(server.Timeout) * time.Second))
		return cli, true, nil
	}
	return nil, false, errors.New("cannot find server")
}

//NewRemoteServer ...
func NewRemoteServer(config *p.LocalConfig) *RemoteServer {
	return &RemoteServer{config}
}
