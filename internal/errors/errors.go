package apie

import "errors"

var (
	// service package errors
	ErrIncorrectUsernameOrPassword = errors.New("username or password is incorrect")
	ErrNoContent                   = errors.New("no input content")
	ErrAccessIsExpired             = errors.New("access token is expired")
	ErrRefreshIsExpired            = errors.New("refresh token is expired")
	ErrNewIp                       = errors.New("ip is change")
	ErrInvalidToken                = errors.New("invalid token")
	ErrConversationProblem         = errors.New("type conversation problem")
	ErrSessionNotFound             = errors.New("session is not found")
	// database package errors
	ErrConnectTimeout = errors.New("connetion timeout")
	ErrInvalidUrl     = errors.New("invalid url")
	ErrUrlExist       = errors.New("url exists")
	// repository package errors
	ErrUserNotFound    = errors.New("user not found")
	ErrRefreshNotFound = errors.New("refresh token not found")
)
