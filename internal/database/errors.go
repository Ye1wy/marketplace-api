package database

import "errors"

var (
	ErrConnectTimeout = errors.New("connetion timeout")
	ErrInvalidUrl     = errors.New("invalid url")
	ErrUrlExist       = errors.New("url exists")
)
