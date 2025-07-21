package repository

import "errors"

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrRefreshNotFound = errors.New("refresh token not found")
)
