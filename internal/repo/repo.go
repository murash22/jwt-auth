package repo

import (
	"auth_service/internal/models"
	"context"
)

type Repo interface {
	RefreshTokenRepo
}

type RefreshTokenRepo interface {
	GetRefreshTokenByUserId(ctx context.Context, userId string) (*models.RefreshToken, error)
	DeleteRefreshTokenByUserId(ctx context.Context, userId string) error
	InsertRefreshToken(ctx context.Context, token *models.RefreshToken) error
}
