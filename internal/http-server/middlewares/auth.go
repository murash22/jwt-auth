package middlewares

import (
	"auth_service/internal/service"
	"context"
	"log/slog"
	"net/http"
	"strings"
)

func NewAuthMiddleware(logger *slog.Logger, secret []byte) func(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			authHeaderParts := strings.Split(authHeader, " ")
			if authHeader == "" || len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
				logger.Info("missing or invalid authorization header", "auth_header", authHeader)
				http.Error(w, "bad token", http.StatusBadRequest)
				return
			}
			token, err := service.VerifyJwtToken(authHeaderParts[1], secret)
			if err != nil {
				logger.Info("invalid token", "err", err)
				http.Error(w, "invalid credentials", http.StatusBadRequest)
				return
			}
			newContext := context.WithValue(r.Context(), "token", token)
			next.ServeHTTP(w, r.WithContext(newContext))
		}
	}
}
