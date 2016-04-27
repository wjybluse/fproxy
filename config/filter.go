package config

import (
	"bufio"
	"net"
	"os"
	"strings"

	gip "github.com/alecthomas/geoip"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("config")
var whitedb []string

//ParserDomain ...
func ParserDomain(domain string) bool {
	ipadress, err := net.LookupIP(domain)
	if err != nil {
		logger.Errorf("cannot find address %s", err)
		return false
	}
	return parser(ipadress[0])
}

func parser(ip net.IP) bool {
	geo, err := gip.New()
	if err != nil {
		logger.Errorf("error when init db,%s", err)
		return false
	}
	country := geo.Lookup(ip)
	if country == nil {
		logger.Error("if address cannot find ,default from china")
		return true
	}
	if strings.Contains(country.String(), "CN") {
		return true
	}
	return false
}

//ParserIP ...
func ParserIP(ip string) bool {
	return parser(net.ParseIP(ip))
}

//IsInWhiteList ...
func IsInWhiteList(domain string) bool {
	if whitedb == nil {
		//load from file
		f, err := os.OpenFile("./config/white.list", os.O_RDONLY, 0660)
		if err != nil {
			logger.Errorf("cannot load white list %s", err)
			return false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			whitedb = append(whitedb, scanner.Text())
		}
		if scanner.Err() != nil {
			logger.Errorf("error when scan the file %s", scanner.Err())
			return false
		}
	}
	for _, line := range whitedb {
		if strings.Contains(domain, line) {
			return true
		}
	}
	return false
}
