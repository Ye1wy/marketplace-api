package apie

import "errors"

var (
	// service package: auth errors
	ErrIncorrectUsernameOrPassword = errors.New("username or password is incorrect")
	ErrNoContent                   = errors.New("no input content")
	ErrAccessIsExpired             = errors.New("access token is expired")
	ErrRefreshIsExpired            = errors.New("refresh token is expired")
	ErrNewIp                       = errors.New("ip is change")
	ErrInvalidToken                = errors.New("invalid token")
	ErrConversationProblem         = errors.New("type conversation problem")
	ErrSessionNotFound             = errors.New("session is not found")
	// service package: ads errors
	ErrInvalidTitle       = errors.New("title is too long or empty/short")
	ErrInvalidDescription = errors.New("description is too long or empty")
	ErrInvalidPrice       = errors.New("price cannot be negative")
	ErrInvalidOrder       = errors.New("order can be only desc or asc")

	// database package errors
	ErrConnectTimeout = errors.New("connetion timeout")
	ErrInvalidUrl     = errors.New("invalid url")
	ErrUrlExist       = errors.New("url exists")
	// repository package errors
	ErrUserNotFound    = errors.New("user not found")
	ErrRefreshNotFound = errors.New("refresh token not found")
)
