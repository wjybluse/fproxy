package config

import (
	"bufio"
	"fmt"
	gip "github.com/alecthomas/geoip"
	"net"
	"os"
	"strings"
)

var whitedb []string

func ParserDomain(domain string) bool {
	ipadress, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf("cannot find address %s", err)
		return false
	}
	return parser(ipadress[0])
}

func parser(ip net.IP) bool {
	geo, err := gip.New()
	if err != nil {
		fmt.Printf("error when init db,%s", err)
		return false
	}
	country := geo.Lookup(ip)
	if country == nil {
		fmt.Println("if address cannot find ,default from china")
		return true
	}
	if strings.Contains(country.String(), "CN") {
		return true
	}
	return false
}

func ParserIP(ip string) bool {
	return parser(net.ParseIP(ip))
}

func IsInWhiteList(domain string) bool {
	if whitedb == nil {
		//load from file
		f, err := os.OpenFile("./white.list", os.O_RDONLY, 0660)
		if err != nil {
			fmt.Printf("cannot load white list %s", err)
			return false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			whitedb = append(whitedb, scanner.Text())
		}
		if scanner.Err() != nil {
			fmt.Printf("error when scan the file %s", scanner.Err())
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
