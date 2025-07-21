package domain

import (
	"time"

	"github.com/google/uuid"
)

type Token struct {
	Ip      string `json:"id"`
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

type RefreshToken struct {
	SessionId uuid.UUID `json:"id"`
	UserId    uuid.UUID `json:"user_id"`
	Refresh   string    `json:"refresh_token"`
	Hash      string    `json:"hash_refresh_token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
