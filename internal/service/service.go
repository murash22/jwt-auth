package service

import (
	"auth_service/internal/config"
	"auth_service/internal/repo"
	"log/slog"
)

type Services struct {
	AuthService *authService
}

func NewServices(logger *slog.Logger, cfg *config.Config, storage repo.Repo) *Services {
	return &Services{
		AuthService: NewAuthService(logger, cfg, storage),
	}
}
