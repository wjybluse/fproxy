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

//FromDomain ...
func FromDomain(domain string) bool {
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

//FromIP ...
func FromIP(ip string) bool {
	return parser(net.ParseIP(ip))
}

//Block ...
func Block(domain string) bool {
	if whitedb == nil {
		//load from file
		f, err := os.OpenFile("./config/white.list", os.O_RDONLY, 0660)
		if err != nil {
			logger.Errorf("[ERROR]:cannot load white list %s\n", err)
			return false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			whitedb = append(whitedb, scanner.Text())
		}
		if scanner.Err() != nil {
			logger.Errorf("[ERROR]:error when scan the file %s\n", scanner.Err())
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
