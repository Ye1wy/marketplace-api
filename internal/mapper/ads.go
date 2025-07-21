package mapper

import (
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
)

func AdsToRequest(ads domain.Ads) dto.AdsRequest {
	return dto.AdsRequest{
		Title:        ads.Title,
		Descripstion: ads.Description,
		Price:        ads.Price,
		ImageURL:     ads.ImageURL,
	}
}

func AdsToResponse(ads domain.Ads) dto.AdsResponse {
	return dto.AdsResponse{
		Title:        ads.Title,
		Descripstion: ads.Description,
		Price:        ads.Price,
		ImageURL:     ads.ImageURL,
		AuthorName:   ads.AuthorName,
		CreatedAt:    ads.CreatedAt,
		IsMine:       ads.IsMine,
	}
}

func AdsToDomain(ads dto.AdsRequest) domain.Ads {
	return domain.Ads{
		Title:       ads.Title,
		Description: ads.Descripstion,
		Price:       ads.Price,
		ImageURL:    ads.ImageURL,
	}
}
