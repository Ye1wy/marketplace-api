package mapper

import (
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
)

func UserToLogin(dom domain.User) dto.LoginRequest {
	return dto.LoginRequest{
		Username: dom.Username,
		Password: "",
	}
}

func LoginToDomain(dto dto.LoginRequest) domain.User {
	return domain.User{
		Username: dto.Username,
		Password: dto.Password,
	}
}
