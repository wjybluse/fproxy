#!/bin/bash

#install golang before
check_golang(){
  #default install brew before
  #brew install golang
  os=`uname`
  if [ "X$uname" = "XDarwin" ];then
    brew install golang
  else
    redhat=`cat /etc/redhat-release`
    if [ "X$redhat" = "X" ]; then
      sudo apt-get install golang
    else
      sudo yum -y install golang
    fi
  fi
  
  if [ $? -ne 0 ]; then
    echo "Please install golang before,and config your go path"
    exit 1
  fi

  #set go path
  gopath=`echo $GOPATH`
  if [[ "X$gopath" = "X" ]]; then
    echo "Settting your go path before"
    exit 1
  fi

  echo "Starting install golang"
}

dependecies(){
  go get gopkg.in/kothar/brotli-go.v0
  go get github.com/op/go-logging
  go get github.com/alecthomas/geoip
  if [[ $? -ne 0 ]]; then
    echo "Install dependecies error"
    exit 1
  fi
}

install(){
  go get github.com/elians/fproxy
  cd $GOPATH
  go build src/github.com/elians/fproxy/local.go
  go build src/github.com/elians/fproxy/server.go
  #create folder if not exsit
  mkdir -p fproxy/config
  mkdir -p fproxy/certs
  mv local server fproxy
  cp src/github.com/elians/fproxy/tpl/* fproxy/config
  echo "the package in $GOPATH/fproxy"
  #current for linux and unix like system
  gen
  mv fproxy.key fproxy.pem fproxy/certs
}

gen(){
  openssl req -x509 -newkey rsa:2048 -keyout fproxy.key -out fproxy.pem -days 365
  if [ $? -ne 0 ]; then
    echo "generate cert file error,pls check openssl is ok or not"
    exit 1
  fi
}

#Starting install
check_golang
dependecies
install
