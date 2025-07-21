package mapper

import (
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
)

func UserToRegister(dom domain.User) dto.Register {
	return dto.Register{
		Username: dom.Username,
		Password: "",
		Email:    dom.Email,
	}
}

func RegisterToDomain(dto dto.Register) domain.User {
	return domain.User{
		Username: dto.Username,
		Password: dto.Password,
		Email:    dto.Email,
	}
}
