package config

import (
	"testing"
)

func TestCompressedAndDeCompressed(t *testing.T) {
	simple := []byte("this is a simple test")
	buf, err := compressedBuffer(simple)
	if err != nil {
		t.Fatalf("error message %s", err)
		t.Fail()
	}
	t.Logf("find buf compressed %s", string(buf[:len(buf)]))
	de, err := decompressBuffer(buf)
	if err != nil {
		t.Fatalf("decompressed error %s", err)
		t.Fail()
	}
	result := string(de[:len(de)])
	source := string(simple[:len(simple)])
	if result != source {
		t.Fatalf("error result source %s,result %s", source, result)
		t.Fail()
	}
}
