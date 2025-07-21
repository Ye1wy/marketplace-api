package service

import (
	apie "auth-service/internal/errors"
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"fmt"
	"strings"
)

type AdsReader interface {
	GetAll(ctx context.Context, filters domain.Filters) ([]domain.Ads, error)
}

type AdsWriter interface {
	Create(ctx context.Context, ads domain.Ads) error
}

type AdsService struct {
	adsReader AdsReader
	adsWriter AdsWriter
	logger    *logger.Logger
}

func NewAdsService(reader AdsReader, writer AdsWriter, userReader UserRead, logger *logger.Logger) *AdsService {
	return &AdsService{
		adsReader: reader,
		adsWriter: writer,
		logger:    logger,
	}
}

func (s *AdsService) Create(ctx context.Context, ads domain.Ads) error {
	op := "service.adsService.Create"

	if len(strings.TrimSpace(ads.Title)) < 5 || len(ads.Title) > 100 {
		s.logger.Warn("Title is greater of 100 or less of 5", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrInvalidTitle)
	}

	if ads.Description != "" && len(ads.Description) > 2000 {
		s.logger.Warn("Description is greater of 2000 or empty", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrInvalidDescription)
	}

	if ads.Price < 0 {
		s.logger.Warn("Price is negative", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrInvalidPrice)
	}

	if err := s.adsWriter.Create(ctx, ads); err != nil {
		s.logger.Error("Failed to create ads", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %v", op, err)
	}

	return nil
}

func (s *AdsService) GetAll(ctx context.Context, filters domain.Filters) ([]domain.Ads, error) {
	op := "service.adsService.GetAll"

	if (filters.Order != "desc") && (filters.Order != "asc") {
		s.logger.Warn("Invalid order", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidOrder)
	}

	ads, err := s.adsReader.GetAll(ctx, filters)
	if err != nil {
		s.logger.Error("Failed to get all ads", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return ads, nil
}
