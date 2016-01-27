package config

import (
	"fmt"
	"testing"
)

func TestFindIP(t *testing.T) {
	result := ParserDomain("youku.com")
	fmt.Printf("find result %v", result)
}

func TestFindChina(t *testing.T) {
	result := ParserIP("220.181.185.141")
	fmt.Printf("from china %v", result)
}
