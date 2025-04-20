package service

import (
	"auth_service/internal/config"
	"context"
	"log/slog"
)

type emailService struct {
}

func NewEmailService(logger *slog.Logger, cfg *config.Config) *emailService {
	return &emailService{}
}

func (s *emailService) Notify(ctx context.Context, userId string, data interface{}) error {
	return nil
}
