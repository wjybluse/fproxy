package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/local"
)

func main() {
	conf := config.Create("./config/conf.json", config.Conf{})
	local.Server(conf.(config.Conf))
}
