package protcol

import (
	"encoding/base64"
	"fmt"
	"github.com/elians/fproxy/config"
	client "github.com/elians/fproxy/conn"
	"io"
	"net"
	"net/http"
	"strings"
)

var (
	HTTP_200 = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	HTTP_407 = []byte("HTTP/1.1 407 Proxy Authorization Required\r\nProxy-Authenticate: Basic realm=\"Secure Proxys\"\r\n\r\n")
)

type HProxy struct {
	listener net.Listener
	cfg      *config.FileConfig
}

func NewHPProxy(listener net.Listener, cfg *config.FileConfig) *HProxy {
	return &HProxy{listener: listener, cfg: cfg}
}

func (h *HProxy) Handle() {
	err := http.Serve(h.listener, h)
	if err != nil {
		fmt.Printf("handle error server error when ")
		return
	}
	fmt.Printf("handle listener ..... start")
}

func (h *HProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("handle error when clean...%s", err)
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
		fmt.Printf("handle hj error %s", err)
		return
	}
	hst := req.URL.Host
	domain := strings.Split(hst, ":")[0]
	if ip := net.ParseIP(domain); ip != nil {
		if config.ParserIP(domain) {
			handleChina(cli, hst)
			return
		}
		h.handleTunnel(cli, hst)
		return
	}
	if config.ParserDomain(domain) && !config.IsInWhiteList(domain) {
		handleChina(cli, hst)
		return
	}
	h.handleTunnel(cli, hst)

}

func (h *HProxy) handleHttp(rw http.ResponseWriter, req *http.Request) {
	hj := rw.(http.Hijacker)
	cli, _, err := hj.Hijack()
	if err != nil {
		fmt.Printf("cannot find hijack file %s", err)
		return
	}
	hst := req.URL.Host
	domain := strings.Split(hst, ":")[0]
	if ip := net.ParseIP(domain); ip != nil {
		if config.ParserIP(domain) {
			handleChina(cli, hst)
			return
		}
		h.handleTunnel(cli, hst)
		return
	}
	if config.ParserDomain(domain) && !config.IsInWhiteList(domain) {
		handleChina(cli, hst)
		return
	}
	h.handleTunnel(cli, hst)
}

func (h *HProxy) handleSimpleHttp() {
	//for simple http todo

}

func (h *HProxy) handleTunnel(con net.Conn, domain string) {
	defer func() {
		con.Close()
	}()
	con.Write(HTTP_200)
	ci, flag, err := client.NewSP(h.cfg).ChooseServer()
	if err != nil {
		fmt.Printf("create server client error %s", err)
		return
	}
	if flag {
		cli := ci.(*client.SSLClient)
		defer func() {
			cli.Conn.Close()
			fmt.Println("local proxy closed...")
		}()
		go io.Copy(&cli.Conn, con)
		io.Copy(con, &cli.Conn)
		return
	}
	cli := ci.(*client.Client)
	defer func() {
		cli.Conn.Close()
		fmt.Println("local proxy closed...")
	}()
	go io.Copy(cli.Conn, con)
	io.Copy(con, cli.Conn)
}

func handleChina(con net.Conn, host string) {
	defer func() {
		con.Close()
	}()
	con.Write(HTTP_200)
	cli := client.NewClient(host)
	if cli == nil {
		fmt.Println("error when create client")
		return
	}
	defer func() {
		cli.Close()
	}()
	io.Copy(cli.Conn, con)
	io.Copy(con, cli.Conn)
}

func (h *HProxy) auth(rw http.ResponseWriter, req *http.Request) bool {
	auth := req.Header.Get("Proxy-Authorization")
	pair := strings.Replace(auth, "Basic ", "", 1)
	userPass, err := base64.StdEncoding.DecodeString(pair)
	if err != nil {
		fmt.Printf("handle err msg %s", err)
		return false
	}
	users := strings.Split(string(userPass), ":")
	if len(users) < 2 {
		fmt.Printf("Auth failed length %d", len(users))
		writeAuthFailed(rw)
		return false
	}
	if users[0] == "" || users[1] == "" {
		fmt.Printf("auth failed..%s", users)
		writeAuthFailed(rw)
		return false
	}
	return users[0] == h.cfg.Username && users[1] == h.cfg.Password

}

func writeAuthFailed(rw http.ResponseWriter) {
	hj, _ := rw.(http.Hijacker)
	client, _, err := hj.Hijack()
	if err != nil {
		fmt.Println("Fail to get Tcp connection of Client")
		return
	}
	defer client.Close()

	client.Write(HTTP_407)
}
