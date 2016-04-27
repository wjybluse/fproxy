package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/server"
)

func main() {
	sf := config.NewRemoteConfig("./config/server.json")
	server.Server(sf)
}
