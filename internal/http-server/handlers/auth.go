package handlers

import (
	"auth_service/internal/dto"
	resp "auth_service/internal/http-server/response"
	"auth_service/internal/service"
	"context"
	"errors"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"strings"
)

var (
	ErrInvalidUserId = errors.New("invalid user id")
)

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

//go:generate go run github.com/vektra/mockery/v2@v2.53.3 --name=TokensProvider
type TokensProvider interface {
	GenerateTokensPair(ctx context.Context, inp *dto.GenerateTokensPairInput) (*dto.GenerateTokensPairOutput, error)
	UpdateTokens(ctx context.Context, inp *dto.UpdateTokensInput) (*dto.UpdateTokensOutput, error)
}

func NewAuthAccessHandler(logger *slog.Logger, s TokensProvider, cookieTTLHours int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		guid := r.URL.Query().Get("user_id")
		if guid == "" {
			logger.Error("user_id wasn't provided")
			w.WriteHeader(http.StatusBadRequest)
			resp.SendResponse(w, ErrInvalidUserId.Error())
			return
		}
		if uuid.Validate(guid) != nil {
			logger.Error("invalid user id provided", "guid", guid)
			w.WriteHeader(http.StatusBadRequest)
			resp.SendResponse(w, ErrInvalidUserId.Error())
			return
		}
		tokensPair, err := s.GenerateTokensPair(r.Context(), &dto.GenerateTokensPairInput{
			UserId: guid,
			Addr:   r.RemoteAddr, // address:port
		})
		if err != nil {
			logger.Error("error while generating tokens", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			resp.SendResponse(w, http.StatusText(http.StatusInternalServerError))
			return
		}
		accessToken, refreshToken := tokensPair.AccessToken, tokensPair.RefreshToken
		response := AuthResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}
		setAuthCookies(w, refreshToken, cookieTTLHours)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp.SendResponse(w, response)
		logger.Info("access token generated")
	}
}

//go:generate go run github.com/vektra/mockery/v2@v2.53.3 --name=Notifier
type Notifier interface {
	Notify(ctx context.Context, userId string, data interface{}) error
}

func NewAuthRefreshHandler(
	logger *slog.Logger,
	s TokensProvider,
	notifier Notifier,
	cookieTTLHours int,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := r.Cookie("refresh-token")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				logger.Error("no refresh token in cookies")
				w.WriteHeader(http.StatusBadRequest)
				resp.SendResponse(w, http.StatusText(http.StatusBadRequest))
			default:
				logger.Error("error while getting refresh token from cookie", "err", err)
				w.WriteHeader(http.StatusInternalServerError)
				resp.SendResponse(w, http.StatusText(http.StatusInternalServerError))
			}
			return
		}
		updatedTokensOutput, err := s.UpdateTokens(r.Context(), &dto.UpdateTokensInput{
			RefreshToken: refreshToken.Value,
			Addr:         r.RemoteAddr,
		})
		if err != nil {
			logger.Error("error while updating tokens", "err", err)
			switch {
			case errors.Is(err, service.ErrInvalidToken), errors.Is(err, service.ErrVerifyingToken):
				w.WriteHeader(http.StatusBadRequest)
				resp.SendResponse(w, err.Error())
			default:
				w.WriteHeader(http.StatusInternalServerError)
				resp.SendResponse(w, http.StatusText(http.StatusInternalServerError))
			}
			return
		}
		prevAddr := strings.Split(updatedTokensOutput.OldRefreshTokenClaims.Addr, ":")[0]
		curAddr := strings.Split(r.RemoteAddr, ":")[0]
		if prevAddr != curAddr {
			err = notifier.Notify(r.Context(), updatedTokensOutput.OldRefreshTokenClaims.Subject, "token updated from new address")
			if err != nil {
				logger.Error("error while notifying new refresh token", "err", err)
			} else {
				logger.Info("user was notified about ip address change", "userId", updatedTokensOutput.OldRefreshTokenClaims.Subject)
			}
		}
		response := AuthResponse{
			AccessToken:  updatedTokensOutput.AccessToken,
			RefreshToken: updatedTokensOutput.RefreshToken,
		}
		setAuthCookies(w, updatedTokensOutput.RefreshToken, cookieTTLHours)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp.SendResponse(w, response)
		logger.Info("refresh token generated")

	}
}

func setAuthCookies(w http.ResponseWriter, refreshToken string, cookieTTLHours int) {
	cookie := http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   cookieTTLHours * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
}
