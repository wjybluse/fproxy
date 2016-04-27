package config

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

//LocalConfig ...
type LocalConfig struct {
	Local     string         `json:"local"`
	LocalPort int            `json:"local_port"`
	Servers   []RemoteConfig `json:"servers"`
	Protcol   string         `json:"protocol"`
	Auth      bool           `json:"auth"`
	Username  string         `json:"proxy_username"`
	Password  string         `json:"proxy_password"`
	Timeout   int            `json:"timeout"`
}

//RemoteConfig ...
type RemoteConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	//for future
	Password string `json:"password"`
	Timeout  int    `json:"timeout"`
	//for future
	Protcol  string `json:"protocol"`
	SSL      bool   `json:"is_ssl"`
	Compress bool   `json:"is_compress"`
}

//NewLocalConfig ...
func NewLocalConfig(file string) *LocalConfig {
	f, err := os.Open(file)
	if err != nil {
		logger.Errorf("open file error...%s\n", err)
		os.Exit(1)
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		logger.Errorf("cannot read data %s", err)
		os.Exit(1)
	}
	var conf LocalConfig
	if err := json.Unmarshal(data, &conf); err != nil {
		logger.Errorf("parser json error %s", err)
		os.Exit(1)
	}
	return &conf
}

//NewRemoteConfig ...
func NewRemoteConfig(filename string) *RemoteConfig {
	f, err := os.Open(filename)
	if err != nil {
		logger.Errorf("Server:---->error when read config file %s", err)
		panic("Server-->cannot find config file,pls check it " + err.Error())
	}
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		logger.Errorf("read data error %s", err)
		panic("Server--->parser file error " + err.Error())
	}
	var vpsConfig RemoteConfig
	if err := json.Unmarshal(buf, &vpsConfig); err != nil {
		logger.Errorf("parser file error ...%s", err)
		panic("Server--->error " + err.Error())
	}
	return &vpsConfig
}
