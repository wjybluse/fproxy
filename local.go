package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/local"
)

func main() {
	conf := config.NewLocalConfig("./config/conf.json")
	local.Server(conf)
}
