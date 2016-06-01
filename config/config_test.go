package config

import (
	"fmt"
	"testing"
)

func TestParserOK(t *testing.T) {
	cf := Create("../tpl/conf.json", Conf{})
	lc := cf.(Conf)
	if lc.Local != "127.0.0.1" {
		t.Fatalf("error...%s", lc.Local)
		t.Fail()
	}
	fmt.Printf("find value local %s,local port %d, vps %v", lc.Local, lc.LocalPort, lc.Servers)
}
