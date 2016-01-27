package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type FileConfig struct {
	Local     string      `json:"local"`
	LocalPort int         `json:"local_port"`
	Servers   []RemoteVPS `json:"servers"`
	Protcol   string      `json:"protcol"`
	Auth      bool        `json:"auth"`
	Username  string      `json:"proxy_username"`
	Password  string      `json:"proxy_password"`
}

type RemoteVPS struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Timeout  int    `json:"timeout"`
	Encrypt  string `json:"encrypt"`
	Protcol  string `json:"protcol"`
	SSL      bool   `json:"is_ssl"`
	Compress bool   `json:"is_compress"`
}

func NewConfigFile(file string) *FileConfig {
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("open file error...%s", err)
		os.Exit(1)
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Printf("cannot read data %s", err)
		os.Exit(1)
	}
	var conf FileConfig
	if err := json.Unmarshal(data, &conf); err != nil {
		fmt.Printf("parser json error %s", err)
		os.Exit(1)
	}
	return &conf
}

func NewServerConfig(filename string) *RemoteVPS {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Server:---->error when read config file %s", err)
		os.Exit(1)
	}
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Printf("read data error %s", err)
		os.Exit(1)
	}
	var vpsConfig RemoteVPS
	if err := json.Unmarshal(buf, &vpsConfig); err != nil {
		fmt.Printf("parser file error ...%s", err)
		os.Exit(1)
	}
	return &vpsConfig
}
