package config

import "time"

type handler func(time.Time) error

//SetTimeout ...
func SetTimeout(fn handler, expireTime int) {
	fn(time.Now().Add(time.Duration(expireTime) * time.Second))
}
