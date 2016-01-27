package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/local"
)

func main() {
	conf := config.NewConfigFile("./conf.json")
	local.CreateLocalServer(conf)
}
