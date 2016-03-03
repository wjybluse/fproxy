package protocol

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"github.com/op/go-logging"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

var logger = logging.MustGetLogger("protocol")

var (
	HTTP_200 = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	HTTP_407 = []byte("HTTP/1.1 407 Proxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"Secure Proxys\"\r\n\r\n")
)

type HProxy struct {
	listener net.Listener
	cfg      *config.FileConfig
	tr       *http.Transport
}

func NewHPProxy(listener net.Listener, cfg *config.FileConfig) *HProxy {
	return &HProxy{listener: listener, cfg: cfg, tr: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
}

func (h *HProxy) Handle() {
	err := http.Serve(h.listener, h)
	if err != nil {
		logger.Errorf("http----->handle error server error when ")
		return
	}
	logger.Errorf("http----->handle listener ..... start")
}

func (h *HProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("http----->handle error when clean...%s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
		}
	}()

	//if need auth,support simple basic auth
	if h.cfg.Auth {
		if !h.auth(rw, req) {
			return
		}
	}

	meth := strings.ToLower(req.Method)
	if meth == "connect" {
		h.handleHttps(rw, req)
		return
	}
	h.handleHttp(rw, req)
}

func (h *HProxy) handleHttps(rw http.ResponseWriter, req *http.Request) {
	hj := rw.(http.Hijacker)
	cli, _, err := hj.Hijack()
	if err != nil {
		logger.Errorf("http----->handle hijack error %s", err)
		return
	}
	hst := req.URL.Host
	domain, port := h.getHostAndPort("https", hst)
	if ip := net.ParseIP(domain); ip != nil {
		if config.ParserIP(domain) {
			handleChina(cli, hst)
			return
		}
		h.handleTunnel(cli, domain, port, false)
		return
	}
	if config.ParserDomain(domain) && !config.IsInWhiteList(domain) {
		handleChina(cli, hst)
		return
	}
	h.handleTunnel(cli, domain, port, true)

}

func (h *HProxy) getHostAndPort(scheme string, hst string) (host string, port int) {
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

func (h *HProxy) handleHttp(rw http.ResponseWriter, req *http.Request) {
	clearProxyHeader(req)
	hst := req.URL.Host
	domain, port := h.getHostAndPort("http", hst)
	if ip := net.ParseIP(domain); ip != nil {
		if config.ParserIP(domain) {
			h.handleSimpleHttp(rw, req)
			return
		}
		h.handleHttpTunnel(rw, req, domain, port, false)
		return
	}
	if config.ParserDomain(domain) && !config.IsInWhiteList(domain) {
		h.handleSimpleHttp(rw, req)
		return
	}
	h.handleHttpTunnel(rw, req, domain, port, true)
}

func (h *HProxy) handleHttpTunnel(rw http.ResponseWriter, req *http.Request, domain string, port int, isdomain bool) {
	ci, flag, err := client.NewSP(h.cfg).ChooseServer()
	if err != nil {
		logger.Errorf("Http--->create server client error %s", err)
		return
	}
	if flag {
		cli := ci.(*client.SSLClient)
		defer func() {
			cli.Conn.Close()
		}()
		err := h.handleSocks5(domain, port, isdomain, &cli.Conn)
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
	err = h.handleSocks5(domain, port, isdomain, cli.Conn)
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

func (h *HProxy) handleSimpleHttp(rw http.ResponseWriter, req *http.Request) {
	resp, err := h.tr.RoundTrip(req)
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
	for key, _ := range headers {
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

func (h *HProxy) handleTunnel(con net.Conn, host string, port int, isdomain bool) {
	con.Write(HTTP_200)
	ci, flag, err := client.NewSP(h.cfg).ChooseServer()
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
		err := h.handleSocks5(host, port, isdomain, &cli.Conn)
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
	err = h.handleSocks5(host, port, isdomain, cli.Conn)
	if err != nil {
		logger.Errorf("Http--->handle error message %s\n", err)
		return
	}
	pipe(cli.Conn, con)
}

func (h *HProxy) handleSocks5(host string, port int, isdomain bool, write io.Writer) error {
	data := make([]byte, 260)
	pos := 0
	if isdomain {
		data[pos] = DOMAIN
		pos++
		data[pos] = byte(len(host))
		pos++
		pos += copy(data[pos:], []byte(host))
	} else {
		data[pos] = IPV4
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
	con.Write(HTTP_200)
	cli := client.NewClient(host)
	if cli == nil {
		logger.Errorf("http----->error when create client")
		return
	}
	defer func() {
		cli.Close()
		con.Close()
	}()
	pipe(cli.Conn, con)
}

func (h *HProxy) auth(rw http.ResponseWriter, req *http.Request) bool {
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
	return users[0] == h.cfg.Username && users[1] == h.cfg.Password

}

func writeAuthFailed(rw http.ResponseWriter) {
	hj, _ := rw.(http.Hijacker)
	client, _, err := hj.Hijack()
	if err != nil {
		logger.Errorf("http----->Fail to get Tcp connection of Client")
		return
	}
	defer client.Close()

	client.Write(HTTP_407)
}
