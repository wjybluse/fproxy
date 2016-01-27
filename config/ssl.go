package config

import (
	"crypto/tls"
	"flag"
	"fmt"
)

var (
	keyFile  = flag.String("keyfile", "./fuck.key", "for ssl use")
	certFile = flag.String("certfile", "./fuck.pem", "for ssl use")
)

func NewSSLConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		fmt.Printf("ERROR:---->cannot load file %s\n", err)
		return nil
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true}
}
