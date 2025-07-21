package repository

import (
	"auth-service/pkg/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

type baseRepo struct {
	db     *pgxpool.Pool
	logger *logger.Logger
}

func NewBaseRepo(db *pgxpool.Pool, logger *logger.Logger) *baseRepo {
	return &baseRepo{
		db,
		logger,
	}
}
