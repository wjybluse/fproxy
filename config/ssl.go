package config

import (
	"crypto/tls"
	"flag"
)

var (
	keyFile  = flag.String("keyfile", "./certs/fproxy.key", "for ssl use")
	certFile = flag.String("certfile", "./certs/fproxy.pem", "for ssl use")
)

//NewSSLConfig ...
func NewSSLConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		logger.Errorf("ERROR:---->cannot load file %s\n", err)
		return nil
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
}
