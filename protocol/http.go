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

type httpHandler struct {
	listener net.Listener
	cfg      *config.Conf
	tr       *http.Transport
}

//NewHTTPTunnel ...
func NewHTTPTunnel(listener net.Listener, cfg *config.Conf) Tunnel {
	return &httpHandler{listener: listener, cfg: cfg, tr: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
}

func (hr *httpHandler) Handle() {
	err := http.Serve(hr.listener, hr)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle error server error when ")
		return
	}
	logger.Errorf("[HTTP_ERROR]:handle listener ..... start")
}

func (hr *httpHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("[HTTP_ERROR]:handle error when clean...%s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
		}
	}()

	meth := strings.ToLower(req.Method)
	if meth == "connect" {
		hr.httpsTrans(rw, req)
		return
	}
	hr.handleHTTP(rw, req)
}

func (hr *httpHandler) httpsTrans(rw http.ResponseWriter, req *http.Request) {
	hj := rw.(http.Hijacker)
	cli, _, err := hj.Hijack()
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle hijack error %s", err)
		return
	}
	hst := req.URL.Host
	domain, port := hr.getHostAndPort("https", hst)
	if ip := net.ParseIP(domain); ip != nil {
		if config.FromIP(domain) {
			cli.Write(httpOk)
			internal(cli, hst)
			return
		}
		hr.trans(cli, domain, port, false)
		return
	}
	if config.FromDomain(domain) && !config.Block(domain) {
		cli.Write(httpOk)
		internal(cli, hst)
		return
	}
	hr.trans(cli, domain, port, true)
}

func (hr *httpHandler) getHostAndPort(scheme string, hst string) (host string, port int) {
	arr := strings.Split(hst, ":")
	host = arr[0]
	if len(arr) < 2 {
		port = 80
		if scheme == "https" {
			port = 443
		}
		return
	}
	port, _ = strconv.Atoi(arr[1])
	return
}

func (hr *httpHandler) handleHTTP(rw http.ResponseWriter, req *http.Request) {
	clearProxyHeader(req)
	hst := req.URL.Host
	domain, port := hr.getHostAndPort("http", hst)
	if ip := net.ParseIP(domain); ip != nil {
		if config.FromIP(domain) {
			hr.handleSimpleHTTP(rw, req)
			return
		}
		hr.httpTrans(rw, req, domain, port, false)
		return
	}
	if config.FromDomain(domain) && !config.Block(domain) {
		hr.handleSimpleHTTP(rw, req)
		return
	}
	hr.httpTrans(rw, req, domain, port, true)
}

func (hr *httpHandler) httpTrans(rw http.ResponseWriter, req *http.Request, domain string, port int, isdomain bool) {
	connector, err := client.NewClient(*hr.cfg)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:create server client error %s", err)
		return
	}

	defer connector.Destory()
	conn, _ := connector.Connect()

	err = handleSocks5(domain, port, isdomain, conn)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle error message %s\n", err)
		return
	}
	if err = req.Write(conn); err != nil {
		logger.Errorf("[HTTP_ERROR]:write data error %s\n", err)
		return
	}
	rsp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:read response error %s\n", err)
		return
	}
	defer rsp.Body.Close()
	//clearHeaders(rw.Header())
	//copyHeaders(rw.Header(), rsp.Header)
	clearAndCopy(rw.Header(), rsp.Header)
	rw.WriteHeader(rsp.StatusCode)
	if _, err = io.Copy(rw, rsp.Body); err != nil {
		logger.Errorf("[HTTP_ERROR]:copy response error %s\n", err)
		return
	}
}

func clearAndCopy(dest, src http.Header) {
	clearHeaders(dest)
	copyHeaders(dest, src)
}

func (hr *httpHandler) handleSimpleHTTP(rw http.ResponseWriter, req *http.Request) {
	resp, err := hr.tr.RoundTrip(req)
	if err != nil {
		http.Error(rw, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	clearAndCopy(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	_, err = io.Copy(rw, resp.Body)
	if err != nil && err != io.EOF {
		logger.Errorf("[HTTP_ERROR]:find error message %s\n", err)
		return
	}
}

func pipe(dest, src net.Conn) {
	go io.Copy(dest, src)
	io.Copy(src, dest)
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

func (hr *httpHandler) trans(con net.Conn, host string, port int, isdomain bool) {
	con.Write(httpOk)
	connector, err := client.NewClient(*hr.cfg)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:create server client error %s \n", err)
		return
	}
	defer connector.Destory()
	conn, _ := connector.Connect()
	err = handleSocks5(host, port, isdomain, conn)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle error message %s\n", err)
		return
	}
	pipe(conn, con)
}

func handleSocks5(host string, port int, isdomain bool, write io.Writer) error {
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
		logger.Errorf("[HTTP_ERROR]:write data error %s\n", err)
		return err
	}
	return nil
}

func internal(con net.Conn, host string) {
	//con.Write(httpOk)
	connector, err := client.NewConnector(host, false)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:error when create client %s \n", err)
		return
	}
	conn, err := connector.Connect()
	defer func() {
		con.Close()
		connector.Destory()
	}()
	pipe(conn, con)
}

func auth(rw http.ResponseWriter, req *http.Request, password string) bool {
	auth := req.Header.Get("Proxy-Authorization")
	pair := strings.Replace(auth, "Basic ", "", 1)
	userPass, err := base64.StdEncoding.DecodeString(pair)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle err msg %s", err)
		return false
	}
	users := strings.Split(string(userPass), ":")
	if len(users) < 2 {
		logger.Errorf("[HTTP_ERROR]:Auth failed length %d", len(users))
		writeAuthFailed(rw)
		return false
	}
	if users[0] == "" || users[1] == "" {
		logger.Errorf("[HTTP_ERROR]:auth failed..%s", users)
		writeAuthFailed(rw)
		return false
	}
	return users[1] == password

}

func writeAuthFailed(rw http.ResponseWriter) {
	hj, _ := rw.(http.Hijacker)
	client, _, err := hj.Hijack()
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:Fail to get Tcp connection of Client")
		return
	}
	defer client.Close()

	client.Write(httpAuthFailed)
}
