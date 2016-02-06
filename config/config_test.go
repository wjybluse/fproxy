package config

import (
	"fmt"
	"testing"
)

func TestParserOK(t *testing.T) {
	cf := NewConfigFile("../tpl/conf.json")
	if cf.Local != "127.0.0.1" {
		t.Fatalf("error...%s", cf.Local)
		t.Fail()
	}
	fmt.Printf("find value local %s,local port %d, vps %v", cf.Local, cf.LocalPort, cf.Servers)
}
