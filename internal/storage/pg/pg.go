package pg

import (
	"auth_service/internal/config"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func New(cfg *config.Config) (*Storage, error) {
	dbPool, err := pgxpool.New(context.Background(), cfg.Db.Url())
	if err != nil {
		return nil, err
	}
	return &Storage{
		pool: dbPool,
	}, nil
}

func (s *Storage) Close() {
	s.pool.Close()
}
