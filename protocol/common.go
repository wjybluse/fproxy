package protocol
import (
    "net"
    "io"
    "os"
    "strings"
    "encoding/binary"
    "bufio"
    "net/http"
    "errors"
    "github.com/elians/fproxy/conn"
    "github.com/op/go-logging"
    gip "github.com/alecthomas/geoip"
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
	ver = 0
	methods = 1

	v5         = 5
	connect = 1

	domainLen = 4
	ipv4      = 1
	ipv6      = 4
	domain    = 3

	ipv4Len    = 3 + 1 + net.IPv4len + 2 //3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	ipv6Len    = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	domainTLen = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
)
//define logger
var logger = logging.MustGetLogger("protocol")

var whitelist []string

//GreenTunnel ...
type GreenTunnel interface{
    Handle()
}

func directConnect(host string,c net.Conn) error {
    //send message directly
    defer c.Close()
    connector,err :=conn.NewConnector(host,false)
    if err!=nil{
      logger.Errorf("[ERROR]:cannot connect to host %s \n", host)
      return err
    }
    //close conenctor after exit
    defer connector.Close()

    c1,_ :=connector.Connect()
    exchange(c1, c)
    return nil
}

//exchange data
func exchange(dest, src net.Conn) {
	go io.Copy(dest, src)
	io.Copy(src, dest)
}

func filterDomain(domain string) bool {
	//use default dns resovler
	ipadress, err := net.LookupIP(domain)
	if err != nil {
		logger.Errorf("[ERROR]:cannot find address %s\n", err)
		return false
	}
	return parser(ipadress[0])
}

func parser(ip net.IP) bool {
	geo, err := gip.New()
	if err != nil {
		logger.Errorf("[ERROR]:error when init db %s\n", err)
		return false
	}
	country := geo.Lookup(ip)
	if country == nil {
		logger.Errorf("[ERROR]:Cannot find domain name %s \n",ip)
		return true
	}
	if strings.Contains(country.String(), "CN") {
		return true
	}
	return false
}


func filterIP(ip string) bool {
	return parser(net.ParseIP(ip))
}

//Block ...
func isblock(domain string) bool {
  //handle whitelist
	if  whitelist == nil {
		//load from file
		f, err := os.OpenFile("./config/white.list", os.O_RDONLY, 0660)
		if err != nil {
			logger.Errorf("[ERROR]:cannot load white list %s\n", err)
			return false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			whitelist = append(whitelist, scanner.Text())
		}
		if scanner.Err() != nil {
			logger.Errorf("[ERROR]:error when scan the file %s\n", scanner.Err())
			return false
		}
	}
  //pattern
	for _, line := range whitelist {
		if strings.Contains(domain, line) {
			return true
		}
	}
	return false
}


func makeSocks5Handshake(host string, port int, noip bool) ([]byte,error) {
	data := make([]byte, 260)
	pos := 0
	if noip {
		data[pos] = domain
		pos++
		data[pos] = byte(len(host))
		pos++
		pos += copy(data[pos:], []byte(host))
	} else if err:=net.ParseIP(host).To4();err!=nil {
		data[pos] = ipv6
		pos++
		pos += copy(data[pos:], net.ParseIP(host).To16())
	}else{
    data[pos] = ipv4
    pos++
    pos += copy(data[pos:], net.ParseIP(host).To4())
  }
	binary.BigEndian.PutUint16(data[pos:], uint16(port))
	pos += 2
	d := data[:pos]
	return d,nil
}

func removeHeaders(req *http.Request) {
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
