package service

import "errors"

var (
	ErrIncorrectUsernameOrPassword = errors.New("username or password is incorrect")
	ErrNoContent                   = errors.New("no input content")
	ErrRefreshIsExpired            = errors.New("refresh token is expired")
	ErrNewIp                       = errors.New("ip is change")
	ErrInvalidToken                = errors.New("invalid token")
	ErrConversationProblem         = errors.New("type conversation problem")
)
