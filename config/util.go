package config

import (
	"errors"
	"gopkg.in/kothar/brotli-go.v0/dec"
	"gopkg.in/kothar/brotli-go.v0/enc"
	"io"
	"time"
)

func decompressBuffer(compressed []byte) ([]byte, error) {
	decompressed, err := dec.DecompressBuffer(compressed, make([]byte, 0))
	if err != nil {
		logger.Errorf("decompressed failed...")
		return nil, err
	}
	return decompressed, nil
}

func compressedBuffer(buffer []byte) ([]byte, error) {
	params := enc.NewBrotliParams()
	//largest compress
	params.SetQuality(11)
	compressed, err := enc.CompressBuffer(params, buffer, make([]byte, 0))
	if err != nil {
		logger.Errorf("compressed failed...%s", err)
		return nil, err
	}
	return compressed, nil
}

func CopyWithCompressed(dst io.Writer, src io.Reader) (written int64, err error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}
	buffer := make([]byte, 32*1024)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			cbuffer, err := compressedBuffer(buffer)
			if err != nil {
				logger.Errorf("error when compress data %s", err)
				break
			}
			nw, err := dst.Write(cbuffer)
			if nw > 0 {
				written += int64(nw)
			}
			if nw != len(cbuffer) {
				logger.Errorf("write buffer error %d", nw)
				err = errors.New("error len when write data")
				break
			}
		}
		if err != nil {
			logger.Errorf("read data error %s", err)
			break
		}
		if err == io.EOF {
			break
		}
	}
	return written, err
}

func CopyWithDecompressed(dst io.Writer, src io.Reader) (written int64, err error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}
	buffer := make([]byte, 32*1024)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			cbuffer, err := decompressBuffer(buffer)
			if err != nil {
				logger.Errorf("error when compress data %s", err)
				break
			}
			nw, err := dst.Write(cbuffer)
			if nw > 0 {
				written += int64(nw)
			}
			if nw != len(cbuffer) {
				logger.Errorf("write buffer error %d", nw)
				err = errors.New("error len when write data")
				break
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Errorf("read data error %s", err)
			break
		}
	}
	return written, err
}

func SetTimeout(fn func(t time.Time) error, expireTime int) {
	fn(time.Now().Add(time.Duration(expireTime) * time.Second))
}