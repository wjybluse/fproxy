package protocol

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("protocol")

var (
	httpOk         = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	httpAuthFailed = []byte("HTTP/1.1 407 Proxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"Secure Proxys\"\r\n\r\n")
)

type httpReceiver struct {
	listener net.Listener
	cfg      *config.LocalConfig
	tr       *http.Transport
}

//NewHTTPTunnel ...
func NewHTTPTunnel(listener net.Listener, cfg *config.LocalConfig) Tunnel {
	return &httpReceiver{listener: listener, cfg: cfg, tr: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
}

func (receiver *httpReceiver) Handle() {
	err := http.Serve(receiver.listener, receiver)
	if err != nil {
		logger.Errorf("http----->handle error server error when ")
		return
	}
	logger.Errorf("http----->handle listener ..... start")
}

func (receiver *httpReceiver) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("http----->handle error when clean...%s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
		}
	}()

	//if need auth,support simple basic auth
	if receiver.cfg.Auth {
		if !receiver.auth(rw, req) {
			return
		}
	}

	meth := strings.ToLower(req.Method)
	if meth == "connect" {
		receiver.handleHTTPS(rw, req)
		return
	}
	receiver.handleHTTP(rw, req)
}

func (receiver *httpReceiver) handleHTTPS(rw http.ResponseWriter, req *http.Request) {
	hj := rw.(http.Hijacker)
	cli, _, err := hj.Hijack()
	if err != nil {
		logger.Errorf("http----->handle hijack error %s", err)
		return
	}
	hst := req.URL.Host
	domain, port := receiver.getHostAndPort("https", hst)
	if ip := net.ParseIP(domain); ip != nil {
		if config.ParserIP(domain) {
			cli.Write(httpOk)
			handleChina(cli, hst)
			return
		}
		receiver.handleTunnel(cli, domain, port, false)
		return
	}
	if config.ParserDomain(domain) && !config.IsInWhiteList(domain) {
		cli.Write(httpOk)
		handleChina(cli, hst)
		return
	}
	receiver.handleTunnel(cli, domain, port, true)
}

func (receiver *httpReceiver) getHostAndPort(scheme string, hst string) (host string, port int) {
	arr := strings.Split(hst, ":")
	if len(arr) < 2 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}

	} else {
		port, _ = strconv.Atoi(arr[1])
	}
	host = arr[0]
	return
}

func (receiver *httpReceiver) handleHTTP(rw http.ResponseWriter, req *http.Request) {
	clearProxyHeader(req)
	hst := req.URL.Host
	domain, port := receiver.getHostAndPort("http", hst)
	if ip := net.ParseIP(domain); ip != nil {
		if config.ParserIP(domain) {
			receiver.handleSimpleHTTP(rw, req)
			return
		}
		receiver.handleHTTPTunnel(rw, req, domain, port, false)
		return
	}
	if config.ParserDomain(domain) && !config.IsInWhiteList(domain) {
		receiver.handleSimpleHTTP(rw, req)
		return
	}
	receiver.handleHTTPTunnel(rw, req, domain, port, true)
}

func (receiver *httpReceiver) handleHTTPTunnel(rw http.ResponseWriter, req *http.Request, domain string, port int, isdomain bool) {
	ci, flag, err := client.NewRemoteServer(receiver.cfg).ChooseServer()
	if err != nil {
		logger.Errorf("Http--->create server client error %s", err)
		return
	}
	if flag {
		cli := ci.(*client.SSLClient)
		defer func() {
			cli.Conn.Close()
		}()
		var err = receiver.handleSocks5(domain, port, isdomain, &cli.Conn)
		if err != nil {
			logger.Errorf("Http--->handle error message %s\n", err)
			return
		}
		if err = req.Write(&cli.Conn); err != nil {
			logger.Errorf("Http->write data error %s\n", err)
			return
		}
		rsp, err := http.ReadResponse(bufio.NewReader(&cli.Conn), nil)
		if err != nil {
			logger.Errorf("Http->read response error %s\n", err)
			return
		}
		defer rsp.Body.Close()
		//clearHeaders(rw.Header())
		//copyHeaders(rw.Header(), rsp.Header)
		clearAndCopy(rw.Header(), rsp.Header)
		if _, err = io.Copy(rw, rsp.Body); err != nil {
			logger.Errorf("http->copy response error %s\n", err)
			return
		}
		return
	}
	cli := ci.(*client.Client)
	defer func() {
		cli.Conn.Close()
	}()
	err = receiver.handleSocks5(domain, port, isdomain, cli.Conn)
	if err != nil {
		logger.Errorf("Http--->handle error message %s\n", err)
		return
	}
	if err = req.Write(cli.Conn); err != nil {
		logger.Errorf("Http->write data error %s\n", err)
		return
	}
	rsp, err := http.ReadResponse(bufio.NewReader(cli.Conn), nil)
	if err != nil {
		logger.Errorf("Http->read response error %s\n", err)
		return
	}
	defer rsp.Body.Close()
	//clearHeaders(rw.Header())
	//copyHeaders(rw.Header(), rsp.Header)
	clearAndCopy(rw.Header(), rsp.Header)
	rw.WriteHeader(rsp.StatusCode)
	if _, err = io.Copy(rw, rsp.Body); err != nil {
		logger.Errorf("http->copy response error %s\n", err)
		return
	}
}

func clearAndCopy(dest, src http.Header) {
	clearHeaders(dest)
	copyHeaders(dest, src)
}

func (receiver *httpReceiver) handleSimpleHTTP(rw http.ResponseWriter, req *http.Request) {
	resp, err := receiver.tr.RoundTrip(req)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	//clearHeaders(rw.Header())
	//copyHeaders(rw.Header(), resp.Header)
	clearAndCopy(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	_, err = io.Copy(rw, resp.Body)
	if err != nil && err != io.EOF {
		logger.Errorf("http----->find error message %s\n", err)
		return
	}
}

func pipe(dest, src interface{}) {
	go io.Copy(dest.(io.Writer), src.(io.Reader))
	io.Copy(src.(io.Writer), dest.(io.Reader))
}

func clearProxyHeader(req *http.Request) {
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("TE")
	req.Header.Del("Trailers")
	req.Header.Del("Transfer-Encoding")
	req.Header.Del("Upgrade")
}

func clearHeaders(headers http.Header) {
	for key := range headers {
		headers.Del(key)
	}
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (receiver *httpReceiver) handleTunnel(con net.Conn, host string, port int, isdomain bool) {
	con.Write(httpOk)
	ci, flag, err := client.NewRemoteServer(receiver.cfg).ChooseServer()
	if err != nil {
		logger.Errorf("create server client error %s", err)
		return
	}
	if flag {
		cli := ci.(*client.SSLClient)
		defer func() {
			cli.Conn.Close()
			con.Close()
		}()
		var err = receiver.handleSocks5(host, port, isdomain, &cli.Conn)
		if err != nil {
			logger.Errorf("Http--->handle error message %s\n", err)
			return
		}
		pipe(&cli.Conn, con)
	}
	cli := ci.(*client.Client)
	defer func() {
		cli.Conn.Close()
	}()
	err = receiver.handleSocks5(host, port, isdomain, cli.Conn)
	if err != nil {
		logger.Errorf("Http--->handle error message %s\n", err)
		return
	}
	pipe(cli.Conn, con)
}

func (receiver *httpReceiver) handleSocks5(host string, port int, isdomain bool, write io.Writer) error {
	data := make([]byte, 260)
	pos := 0
	if isdomain {
		data[pos] = domain
		pos++
		data[pos] = byte(len(host))
		pos++
		pos += copy(data[pos:], []byte(host))
	} else {
		data[pos] = ipv4
		pos++
		pos += copy(data[pos:], net.ParseIP(host).To4())
	}
	binary.BigEndian.PutUint16(data[pos:], uint16(port))
	pos += 2
	d := data[:pos]
	if _, err := write.Write(d); err != nil {
		logger.Errorf("Http--->write data error %s\n", err)
		return err
	}
	return nil
}

func handleChina(con net.Conn, host string) {
	//con.Write(httpOk)
	cli := client.NewClient(host)
	if cli == nil {
		logger.Errorf("http----->error when create client")
		return
	}
	//config.SetTimeout(cli.Conn.SetReadDeadline, 5)
	defer func() {
		logger.Info("close pipline")
		con.Close()
		cli.Close()
	}()
	pipe(cli.Conn, con)
}

func (receiver *httpReceiver) auth(rw http.ResponseWriter, req *http.Request) bool {
	auth := req.Header.Get("Proxy-Authorization")
	pair := strings.Replace(auth, "Basic ", "", 1)
	userPass, err := base64.StdEncoding.DecodeString(pair)
	if err != nil {
		logger.Errorf("http----->handle err msg %s", err)
		return false
	}
	users := strings.Split(string(userPass), ":")
	if len(users) < 2 {
		logger.Errorf("http----->Auth failed length %d", len(users))
		writeAuthFailed(rw)
		return false
	}
	if users[0] == "" || users[1] == "" {
		logger.Errorf("http----->auth failed..%s", users)
		writeAuthFailed(rw)
		return false
	}
	return users[0] == receiver.cfg.Username && users[1] == receiver.cfg.Password

}

func writeAuthFailed(rw http.ResponseWriter) {
	hj, _ := rw.(http.Hijacker)
	client, _, err := hj.Hijack()
	if err != nil {
		logger.Errorf("http----->Fail to get Tcp connection of Client")
		return
	}
	defer client.Close()

	client.Write(httpAuthFailed)
}
