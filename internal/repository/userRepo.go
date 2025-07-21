package repository

import (
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type userRepo struct {
	*baseRepo
}

func NewUserRepo(db *pgxpool.Pool, logger *logger.Logger) *userRepo {
	baseRepo := NewBaseRepo(db, logger)
	return &userRepo{
		baseRepo: baseRepo,
	}
}

func (r *userRepo) Create(ctx context.Context, user domain.User) error {
	op := "repository.user.Create"
	query := "INSERT INTO users(username, password, email) VALUES (@username, @password, @email)"
	args := pgx.NamedArgs{
		"username": user.Username,
		"password": user.Password,
		"email":    user.Email,
	}

	if _, err := r.db.Exec(ctx, query, args); err != nil {
		r.logger.Debug("Creation failed", logger.Err(err), "op", op)
		return fmt.Errorf("repo: Create user failed %v", err)
	}

	return nil
}

func (r *userRepo) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	op := "repository.user.GetByUsername"
	query := "SELECT * FROM users WHERE username=@username"
	arg := pgx.NamedArgs{"username": username}

	row := r.db.QueryRow(ctx, query, arg)
	var user domain.User
	err := row.Scan(&user.Id, &user.Username, &user.Password, &user.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		r.logger.Debug("User not found", "op", op)
		return nil, ErrUserNotFound
	}

	if err != nil {
		r.logger.Debug("Error in scaning user", logger.Err(err), "op", op)
		return nil, fmt.Errorf("User Repo: %v", err)
	}

	return &user, nil
}

func (r *userRepo) GetById(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	op := "repository.user.GetById"
	query := "SELECT * FROM users WHERE id=@id"
	arg := pgx.NamedArgs{"id": id}

	row := r.db.QueryRow(ctx, query, arg)
	var user domain.User
	err := row.Scan(&user.Id, &user.Username, &user.Password, &user.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		r.logger.Debug("User not found", "op", op)
		return nil, ErrUserNotFound
	}

	if err != nil {
		r.logger.Debug("Error in scaning user", logger.Err(err), "op", op)
		return nil, fmt.Errorf("User Repo: %v", err)
	}

	return &user, nil
}
