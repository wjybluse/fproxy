package config

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("config")

//Conf ...
type Conf struct {
	Local     string   `json:"local"`
	SSL       bool     `json:"ssl"`
	LocalPort int      `json:"local_port"`
	Servers   []common `json:"servers"`
	Protocol  string   `json:"protocol"`
	Password  string   `json:"proxy_password"`
	Timeout   int      `json:"timeout"`
	Transport string   `json:"transport"`
}

type common struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

//ServerConf ...
type ServerConf struct {
	common
	Password string `json:"password"`
	Timeout  int    `json:"timeout"`
	Protcol  string `json:"protocol"`
	SSL      bool   `json:"is_ssl"`
}

//Create ...
func Create(filename string, cfg interface{}) {
	f, err := os.Open(filename)
	if err != nil {
		logger.Errorf("[ERROR]:open file error...%s.file name %s\n", err, filename)
		panic("open config file error.")
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		logger.Errorf("[ERROR]:cannot read data %s\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		logger.Errorf("[ERROR]:parser json error %s\n", err)
		os.Exit(1)
	}
}
