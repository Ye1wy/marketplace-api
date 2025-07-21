package domain

import "github.com/google/uuid"

type AccessTokenPayload struct {
	Username  string
	Ip        string
	SessionId uuid.UUID
}

type RefreshTokenPayload struct {
	UserId    uuid.UUID
	SessionId uuid.UUID
}
