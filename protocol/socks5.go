package protocol

import (
	"errors"
	"io"
	"net"
	"strings"
	"encoding/binary"
	"strconv"

	"github.com/elians/fproxy/config"
	c "github.com/elians/fproxy/conn"
)

type socks5Wrap struct {
	conf   *config.Conf
	listener *net.Listener
}

//Socks5Wrap ...
func Socks5Wrap(listener *net.Listener,conf *config.Conf) GreenTunnel {
	return &socks5Wrap{conf, listener}
}

func (sw *socks5Wrap) handshake(conn net.Conn) error {
	//the largest buffer size is 258
	buf := make([]byte, 258)
	var n int
	var err error
	if n, err = io.ReadAtLeast(conn, buf, nmethod+1); err != nil {
		logger.Errorf("[SOCKS_ERROR]:read data error %s\n", err)
		return err
	}
	if buf[version] != socksV5 {
		logger.Errorf("[SOCKS_ERROR]:error version socks %v\n", buf[version])
		return errSocks
	}
	nmethod := int(buf[nmethod])
	msgLen := nmethod + 2
	if n == msgLen {
		//TODO
	} else if msgLen < n {
		return errAuth
	} else {
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			logger.Errorf("[SOCKS_ERROR]:read data error,cannot finish handshake %s\n", err)
			return err
		}
	}
	_, err = conn.Write([]byte{socksV5, 0})
	return err
}

func request(c net.Conn)(string, bool, []byte,error){
	buf := make([]byte, 263)
	var isDomain = false
	var err error
	var n,hostlen,typeLen int
	if n, err = io.ReadAtLeast(c, buf, domainLen+1); err != nil {
		logger.Errorf("[SOCKS_ERROR]:read data from client error %s\n", err)
		return "", false, nil,err
	}
	if buf[version] != socksV5{
		logger.Errorf("[SOCKS_ERROR]:invalid version %b \n",buf[version])
		return  "", false, nil,errSocks
	}
	if buf[1] != socksCmdConnect {
		logger.Errorf("[SOCKS_ERROR]:error socks cmd value is %v\n", buf[1])
		return "", false, nil,errCmd
	}
	ipType := buf[3]
	switch ipType {
	     case ipv4:{
	         hostlen = ipv4Len
		       typeLen = net.IPv4len
				 }
			 case ipv6:{
		       hostlen = ipv6Len
			     typeLen = ipv6Len
				 }
			 case domain:{
			     hostlen = int(buf[domainLen]) + domainTLen
				   typeLen = domainLen
				   isDomain = true
				 }
			 default:{
			     logger.Errorf("[SOCKS_ERROR]:don't know the type of address %b \n",ipType)
				   return "",false,nil,errors.New("invalid address type")}
	}
	if n < hostlen {
		if _, err := io.ReadFull(c, buf[n:hostlen]); err != nil {
			logger.Errorf("[SOCKS_ERROR]:read data error %s\n", err)
			return "", false, nil,err
		}
	} else if n > hostlen {
		logger.Errorf("[SOCKS_ERROR]:some error n is %d,hostlen is %d \n",n,hostlen)
		return "", false,nil, errors.New("error socks data export")
	}
	var host string
	if isDomain{
		host = string(buf[5 : 5+buf[typeLen]])
	}else{
		host = net.IP(buf[4 : 4+typeLen]).String()
	}
	rawAddr := buf[3:hostlen]
	port := binary.BigEndian.Uint16(buf[hostlen-2 : hostlen])
  return net.JoinHostPort(host, strconv.Itoa(int(port))),isDomain,rawAddr,nil
}


func (sw *socks5Wrap) connect(conn net.Conn) {
	if err := sw.handshake(conn); err != nil {
		logger.Errorf("[SOCKS_ERROR]:handshake error %s\n", err)
		return
	}
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		logger.Errorf("[SOCKS_ERROR]:error send data to client %s\n", err)
		return
	}
	defer conn.Close()
	host, domian, rawAddr,err := request(conn)
	if err!=nil{
		logger.Errorf("[SOCKS_ERROR]:handle error message %s \n", err)
		return
	}
	//need connect to remote server or not
	if domian && isblock(strings.Split(host, ":")[0]) {
		if result := filterDomain(strings.Split(host, ":")[0]);result{
			directConnect(host,conn)
			return
		}
	} else if !domian {
		if result := filterIP(strings.Split(host, ":")[0]);result{
			directConnect(host,conn)
			return
		}
	}
	connector, err := c.NewClient(*sw.conf)
	if err != nil {
		logger.Errorf("[SOCKS_ERROR]:connect to server failed %s", err)
		return
	}
	defer connector.Close()
	con, _ := connector.Connect()
	if _, err := con.Write(rawAddr); err != nil {
		logger.Errorf("[SOCKS_ERROR]:handle error message when write data %s \n", err)
		return
	}
	exchange(con, conn)
}

//Handle ...
func (sw *socks5Wrap) Handle() {
	for {
		conn, err := (*sw.listener).Accept()
		if err != nil {
			logger.Errorf("[SOCKS_ERROR]:handle connection error %s\n", err)
			continue
		}
		go sw.connect(conn)
	}
}
