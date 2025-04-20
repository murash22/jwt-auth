package pg

import (
	"auth_service/internal/models"
	"auth_service/internal/storage"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

func (s *Storage) InsertRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	//goland:noinspection SqlResolve
	query := `INSERT INTO refresh_tokens (token_hash, user_id) VALUES (@tokenHash, @userId)`
	args := pgx.NamedArgs{
		"tokenHash": token.TokenHash,
		"userId":    token.UserId,
	}
	_, err := s.pool.Exec(ctx, query, args)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) GetRefreshTokenByUserId(ctx context.Context, userId string) (*models.RefreshToken, error) {
	query := `SELECT * FROM refresh_tokens WHERE user_id = $1`
	rows, err := s.pool.Query(ctx, query, userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	token, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.RefreshToken])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNoSucRecord
		}
		return nil, err
	}
	return &token, nil
}

func (s *Storage) DeleteRefreshTokenByUserId(ctx context.Context, userId string) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`
	t, err := s.pool.Exec(ctx, query, userId)
	if err != nil {
		return err
	}
	if t.RowsAffected() == 0 {
		return storage.ErrNoSucRecord
	}
	return nil
}
