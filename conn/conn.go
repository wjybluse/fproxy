package conn

import (
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"strconv"

	"github.com/elians/fproxy/config"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("conn")

//Connector ...
type Connector interface {
	//destory conncetor
	Connect() (net.Conn, error)
	Close()
}

//Client ...
type client struct {
	Conn net.Conn
}

//SSLClient ...
type sslClient struct {
	Conn *tls.Conn
}

func (cli *client) Connect() (net.Conn, error) {
	return cli.Conn, nil
}

func (cli *client) Close() {
	cli.Conn.Close()
}

func (cli *sslClient) Connect() (net.Conn, error) {
	return net.Conn(cli.Conn), nil
}

func (cli *sslClient) Close() {
	cli.Conn.Close()
}

func createSSLClient(host string) (*sslClient, error) {
	conn, err := tls.Dial("tcp", host, config.SslConfig())
	if err != nil {
		logger.Errorf("[ERROR]:cannnot create ssl client %s\n", err)
		return nil, err
	}
	return &sslClient{conn}, nil
}

func createClient(host string) (*client, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		logger.Errorf("[ERROR]:cannnot create client %s\n", err)
		return nil, err
	}
	return &client{conn}, nil
}

//NewConnector ...
func NewConnector(host string, isSSL bool) (Connector, error) {
	if isSSL {
		return createClient(host)
	}
	return createClient(host)
}

//NewClient ...
func NewClient(conf config.Conf) (Connector, error) {
	if len(conf.Servers) < 0 {
		return nil, errors.New("[ERROR]:No server can be used")
	}
	// use server id after this version
	server, _ := roundRobin(0, conf)
	if conf.SSL {
		cli, err := createSSLClient(server)
		if err != nil {
			logger.Errorf("[ERROR]:create ssl client error.rebalance %s\n", err)
			return nil, err
		}
		return cli, nil
	}
	cli, err := createClient(server)
	if err != nil {
		logger.Errorf("[ERROR]:create client error.rebalance %s\n", err)
		return nil, err
	}
	return cli, nil
}
func roundRobin(serverid int, conf config.Conf) (string, int) {
	if serverid == 0 {
		serverid = rand.Intn(len(conf.Servers))
	}
	server := conf.Servers[serverid]
	return net.JoinHostPort(server.Host, strconv.Itoa(server.Port)), serverid
}
