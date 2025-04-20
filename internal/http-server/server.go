package http_server

import (
	"auth_service/internal/config"
	"auth_service/internal/http-server/handlers"
	"auth_service/internal/service"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

type server struct {
	router *http.ServeMux
	srv    *http.Server
	cfg    *config.Config
}

func New(logger *slog.Logger, cfg *config.Config, services *service.Services) *server {
	srv := &server{
		router: http.NewServeMux(),
		cfg:    cfg,
	}
	srv.initRoutes(logger, services)
	return srv
}

func (s *server) initRoutes(logger *slog.Logger, services *service.Services) {
	s.router.Handle("POST /auth/access", handlers.NewAuthAccessHandler(
		logger, services.AuthService, s.cfg.CookiesTTLHours,
	))
	s.router.Handle("POST /auth/refresh", handlers.NewAuthRefreshHandler(
		logger, services.AuthService, services.EmailService, s.cfg.CookiesTTLHours,
	))
}

func (s *server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *server) Run(ctx context.Context) error {
	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:%s", s.cfg.Server.Host, s.cfg.Server.Port),
		Handler: s.router,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	return s.srv.ListenAndServe()
}
