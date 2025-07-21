package domain

import "github.com/google/uuid"

type AccessTokenPayload struct {
	UserID    uuid.UUID
	Ip        string
	SessionId uuid.UUID
}

type RefreshTokenPayload struct {
	UserId    uuid.UUID
	SessionId uuid.UUID
}
