package http_server

import (
	_ "auth_service/docs"
	"auth_service/internal/config"
	"auth_service/internal/http-server/handlers"
	"auth_service/internal/http-server/middlewares"
	"auth_service/internal/service"
	"context"
	"fmt"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"log/slog"
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
		logger, services.AuthService, s.cfg.CookiesTTLHours,
	))

	authMw := middlewares.NewAuthMiddleware(logger, []byte(s.cfg.JwtSecret))
	s.router.HandleFunc("GET /auth/me", authMw(handlers.NewGetGuidHandler(logger)))
	s.router.HandleFunc("POST /auth/logout", authMw(handlers.NewLogoutHandler(logger, services.AuthService)))

	s.router.Handle("/swagger/", httpSwagger.WrapHandler)
}

func (s *server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func (s *server) Run(ctx context.Context) error {
	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:8080", s.cfg.Server.Host),
		Handler: s.router,
	}

	return s.srv.ListenAndServe()
}
