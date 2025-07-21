package mapper

import (
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
)

func TokenToDomain(token dto.Token) domain.Token {
	return domain.Token{
		Access:  token.Access,
		Refresh: token.Refresh,
	}
}

func TokenToDto(token domain.Token) dto.Token {
	return dto.Token{
		Access:  token.Access,
		Refresh: token.Refresh,
	}
}
