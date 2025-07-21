package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresConfig struct {
	PostgresHost     string        `env:"POSTGRES_HOST" env-default:"localhost"`
	PostgresPort     string        `env:"POSTGRES_PORT" env-default:"5432"`
	PostgresUser     string        `env:"POSTGRES_USER"`
	PostgresPassword string        `env:"POSTGRES_PASSWORD" env-default:"localhost"`
	PostgresDatabase string        `env:"POSTGRES_DB"`
	MaxConn          string        `env:"postgres_db_pool_max_conns" env-default:"20"`
	ConnectTimeout   time.Duration `env:"timeout" env-default:"2s"`
}

func NewPostgresStorage(cfg *PostgresConfig) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeoutCause(context.Background(), cfg.ConnectTimeout, ErrConnectTimeout)
	defer cancel()

	connect := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?pool_max_conns=%s", cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresDatabase, cfg.MaxConn)
	conn, err := pgxpool.New(ctx, connect)
	if err != nil {
		return nil, fmt.Errorf("postgres connection: %v", err)
	}

	return conn, nil
}
