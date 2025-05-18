package handlers

import (
	"auth_service/internal/dto"
	resp "auth_service/internal/http-server/response"
	"auth_service/internal/service"
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
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

type TokensProvider interface {
	GenerateTokensPair(ctx context.Context, inp *dto.GenerateTokensPairInput) (*dto.GenerateTokensPairOutput, error)
}

// @Summary SignIn
// @Tags auth
// @Description Endpoint to get tokens pair
// @ID get-tokens
// @Produce json
// @Produce plain
// @Param user_id query string true "User guid. For example: ac798a7c-8244-414b-9f84-c8e4a61c13c0"
// @Success      200  {object}  AuthResponse  "Successful answer with tokens"
// @Failure      400  {string}  string  "In case if user_id wasn't provided or invalid guid"
// @Failure		 500  {string}  string  "Internal server error"
// @Router       /auth/access [post]
func NewAuthAccessHandler(logger *slog.Logger, s TokensProvider, cookieTTLHours int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		guid := r.URL.Query().Get("user_id")
		if guid == "" {
			logger.Error("user_id wasn't provided")
			resp.SendTextResponse(w, http.StatusBadRequest, ErrInvalidUserId.Error())
			return
		}
		if uuid.Validate(guid) != nil {
			logger.Error("invalid user id provided", "guid", guid)
			resp.SendTextResponse(w, http.StatusBadRequest, ErrInvalidUserId.Error())
			return
		}
		tokensPair, err := s.GenerateTokensPair(r.Context(), &dto.GenerateTokensPairInput{
			UserId:    guid,
			Addr:      strings.Split(r.RemoteAddr, ":")[0],
			UserAgent: r.UserAgent(),
		})
		if err != nil {
			logger.Error("error while generating tokens", "err", err)
			resp.SendTextResponse(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		response := AuthResponse{
			AccessToken:  tokensPair.AccessToken,
			RefreshToken: tokensPair.RefreshToken,
		}
		setAuthCookies(w, tokensPair.RefreshToken, cookieTTLHours)
		resp.SendJSONResponse(w, http.StatusOK, response)
		logger.Info("tokens generated and responded")
	}
}

type TokensUpdater interface {
	UpdateTokens(ctx context.Context, inp *dto.UpdateTokensInput) (*dto.UpdateTokensOutput, error)
}

// @Summary UpdateTokens
// @Tags auth
// @Description Endpoint to update tokens pair. Expects Bearer in Authorization header and refresh-token in Cookie header. When testing in browser, once you update tokens, it is possible to update them with the same input refresh-token, but in fact browser automatically replaces cookies with the one sent from server
// @ID update-tokens
// @Produce json
// @Produce plain
// @Param Authorization header string true "Access token passed in Authorization header. For example 'Bearer paste-here-your-access-token'"
// @Param Cookie header string true "Refresh token passed in cookie header. For example: 'refresh-token=paste-here-your-refresh-token'"
// @Success      200  {object}  AuthResponse  "Successful answer with tokens"
// @Failure      400  {string}  string  "In case if invalid token"
// @Failure		 500  {string}  string  "Internal server error"
// @Router       /auth/refresh [post]
func NewAuthRefreshHandler(
	logger *slog.Logger,
	s TokensUpdater,
	cookieTTLHours int,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := r.Cookie("refresh-token")
		authHeader := strings.Split(r.Header.Get("Authorization"), " ")
		if err != nil || len(authHeader) != 2 || authHeader[0] != "Bearer" {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				logger.Error("no refresh token in cookies")
				resp.SendTextResponse(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
			case len(authHeader) != 2 || authHeader[0] != "Bearer":
				logger.Error("bad access token in auth header ", "authHeader", authHeader)
				resp.SendTextResponse(w, http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
			default:
				logger.Error("error while getting refresh token from cookie", "err", err)
				resp.SendTextResponse(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			}
			return
		}
		updatedTokensOutput, err := s.UpdateTokens(r.Context(), &dto.UpdateTokensInput{
			AccessToken:  authHeader[1],
			RefreshToken: refreshToken.Value,
			Addr:         strings.Split(r.RemoteAddr, ":")[0],
			UserAgent:    r.UserAgent(),
		})
		if err != nil {
			logger.Error("error while updating tokens", "err", err)
			switch {
			case errors.Is(err, service.ErrInvalidToken):
				resp.SendTextResponse(w, http.StatusBadRequest, err.Error())
			case errors.Is(err, service.ErrChangedUserAgent):
				resp.SendTextResponse(w, http.StatusUnauthorized, "trying to update tokens with new user-agent")
			default:
				resp.SendTextResponse(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			}
			return
		}
		response := AuthResponse{
			AccessToken:  updatedTokensOutput.AccessToken,
			RefreshToken: updatedTokensOutput.RefreshToken,
		}
		setAuthCookies(w, updatedTokensOutput.RefreshToken, cookieTTLHours)
		resp.SendJSONResponse(w, http.StatusOK, response)
		logger.Info("refresh token generated")
	}
}

type LogoutService interface {
	Logout(ctx context.Context, userId string) error
}

// @Summary Logout (deletes refresh token in db)
// @Security BearerAuth
// @Tags auth
// @Description Deletes refresh-token in db. Because of that, access_token will be valid until it expires (low TTL). And that's why protected routes will be accessible for a little time
// @ID invalidate-tokens
// @Produce plain
// @Success      200  {string}  string  "Successfully logged out (deleted refresh-token)"
// @Failure		 500  {string}  string  "Internal server error"
// @Router       /auth/logout [post]
func NewLogoutHandler(logger *slog.Logger, s LogoutService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value("token").(*jwt.Token)
		userId, _ := token.Claims.GetSubject()
		err := s.Logout(r.Context(), userId)
		if err != nil {
			resp.SendTextResponse(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		logger.Info("logged out user", "userId", userId)
		resp.SendTextResponse(w, http.StatusOK, http.StatusText(http.StatusOK))
	}
}

// @Summary Get user's GUID
// @Security BearerAuth
// @Tags auth
// @Description Returns user's GUID
// @ID token-subject
// @Produce plain
// @Success      200  {string}  string  "Successfully logged out (deleted refresh-token)"
// @Failure		 500  {string}  string  "Internal server error"
// @Router       /auth/me [get]
func NewGetGuidHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Context().Value("token").(*jwt.Token)
		subject, err := token.Claims.GetSubject()
		if err != nil {
			logger.Error("error getting token subject", "err", err)
			resp.SendTextResponse(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		resp.SendTextResponse(w, http.StatusOK, subject)
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
