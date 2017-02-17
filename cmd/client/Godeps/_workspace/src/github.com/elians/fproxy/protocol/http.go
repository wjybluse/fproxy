package protocol

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
  "github.com/elians/fproxy/conn"
	"github.com/elians/fproxy/config"
)



var (
	httpOk         = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	httpAuthFailed = []byte("HTTP/1.1 407 Proxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"Secure Proxys\"\r\n\r\n")
)

type httpWrap struct {
	listener        *net.Listener
	conf            *config.Conf
	transport       *http.Transport
}

//HTTPWraper ...
func HTTPWraper(listener *net.Listener, conf *config.Conf) GreenTunnel {
	return &httpWrap{listener: listener, conf: conf, transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DisableKeepAlives: true}}
}

func (hr *httpWrap) Handle() {
	err := http.Serve(*hr.listener, hr)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle error server error when ")
		return
	}
	logger.Errorf("[HTTP_ERROR]:handle listener ..... start")
}

func (hr *httpWrap) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			logger.Errorf("[HTTP_ERROR]:handle error when clean...%s\n", err)
			rw.WriteHeader(http.StatusInternalServerError)
		}
	}()

  //if methos is connect,use https default else use http
	if req.Method == "CONNECT"{
		hr.httpsConnect(rw,req)
		return
	}
	hr.httpConnect(rw, req)
}

func (hr *httpWrap) httpsConnect(rw http.ResponseWriter, req *http.Request) {
	hijack, _, err := rw.(http.Hijacker).Hijack()
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle hijack error %s\n", err)
		return
	}
  var host = req.URL.Host
	host, port := parserHost(host)
	if port == 0 {
		//use default https port
		port= 443
	}
	defer func(){
	  if hijack!=nil{
			hijack.Close()
		}
	}()

	ipAddress := net.ParseIP(host)
	if ipAddress == nil{
		logger.Warningf("[WARN]cannot find host info %s \n", host)
		if filterDomain(host) && !isblock(host) {
			hijack.Write(httpOk)
			directConnect(host, hijack)
			return
		}
		hr.httpsTransfor(hijack, host, port, true)
		return
	}
	if filterIP(host) {
		//write message to client.handshake ok
		hijack.Write(httpOk)
		directConnect(host, hijack)
		return
	}
	hr.httpsTransfor(hijack, host, port, false)
}

func parserHost(host string)(string,int) {
	  var arr = strings.Split(host, ":")
		if len(arr)<2{
			return arr[0],0
		}
		port,_ := strconv.Atoi(arr[1])
		return arr[0],port
}


func (hr *httpWrap) httpConnect(rw http.ResponseWriter, req *http.Request) {
	//remove header
	removeHeaders(req)
	host := req.URL.Host
	host, port := parserHost(host)
	if port == 0 {
		port = 80
	}
	if ip := net.ParseIP(host); ip != nil {
		if filterIP(host) {
			hr.directHTTP(rw, req)
			return
		}
		hr.doTransfor(rw, req, host, port, false)
		return
	}
	if filterDomain(host) && !isblock(host) {
		hr.directHTTP(rw, req)
		return
	}
	hr.doTransfor(rw, req, host, port, true)
}

func (hr *httpWrap) doTransfor(rw http.ResponseWriter, req *http.Request, domain string, port int, isdomain bool) {
	connector, err := conn.NewClient(*hr.conf)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:create server client error %s", err)
		return
	}

	defer connector.Close()
	c, _ := connector.Connect()

	data,err := makeSocks5Handshake(domain, port, isdomain)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle error message %s\n", err)
		return
	}
	c.Write(data)
	if err = req.Write(c); err != nil {
		logger.Errorf("[HTTP_ERROR]:write data error %s\n", err)
		return
	}
	rsp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:read response error %s\n", err)
		return
	}
	defer rsp.Body.Close()
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

func (hr *httpWrap) directHTTP(rw http.ResponseWriter, req *http.Request) {
	resp, err := hr.transport.RoundTrip(req)
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

func (hr *httpWrap) httpsTransfor(con net.Conn, host string, port int, isdomain bool) {
	con.Write(httpOk)
	connector, err := conn.NewClient(*hr.conf)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:create server client error %s \n", err)
		return
	}
	defer connector.Close()
	c, _ := connector.Connect()
	data,err := makeSocks5Handshake(host, port, isdomain)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle error message %s\n", err)
		return
	}
	//write data
	c.Write(data)
	exchange(c, con)
}

func authentication(rw http.ResponseWriter, req *http.Request, password string) bool {
	authHeader := req.Header.Get("Proxy-Authorization")
	pair := strings.Replace(authHeader, "Basic ", "", 1)
	userPass, err := base64.StdEncoding.DecodeString(pair)
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:handle err msg %s", err)
		return false
	}
	users := strings.Split(string(userPass), ":")
	if len(users) < 2 {
		logger.Errorf("[HTTP_ERROR]:Auth failed length %d", len(users))
		toFailed(rw)
		return false
	}
	if users[0] == "" || users[1] == "" {
		logger.Errorf("[HTTP_ERROR]:auth failed..%s", users)
		toFailed(rw)
		return false
	}
	return users[1] == password

}

func toFailed(rw http.ResponseWriter) {
	hijack, _, err := rw.(http.Hijacker).Hijack()
	if err != nil {
		logger.Errorf("[HTTP_ERROR]:Fail to get Tcp connection of Client")
		return
	}
	defer hijack.Close()

	hijack.Write(httpAuthFailed)
}
