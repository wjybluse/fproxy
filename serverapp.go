package main

import (
	"github.com/elians/fproxy/config"
	"github.com/elians/fproxy/server"
)

func main() {
	sf := config.NewServerConfig("./server.json")
	server.CreateServer(sf)
}
