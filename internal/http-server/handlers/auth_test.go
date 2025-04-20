package handlers_test

import (
	"auth_service/internal/dto"
	"auth_service/internal/http-server/handlers"
	"auth_service/internal/http-server/handlers/mocks"
	"auth_service/internal/logger"
	"auth_service/internal/service"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthAccessHandler(t *testing.T) {
	cases := []struct {
		name          string
		userId        string
		responseCode  int
		responseError error
		responseBody  string
	}{
		{
			name:          "Bad guid",
			userId:        "f6a16ff7",
			responseCode:  http.StatusBadRequest,
			responseError: handlers.ErrInvalidUserId,
		},
		{
			name:          "Empty guid",
			userId:        "",
			responseCode:  http.StatusBadRequest,
			responseError: handlers.ErrInvalidUserId,
		},
		{
			name:         "Good scenario",
			userId:       "f6a16ff7-4a31-11eb-be7b-8344edc8f36b",
			responseCode: http.StatusOK,
			responseBody: "",
		},
	}
	mockLogger := slog.New(logger.NewMockLogger())
	cookieTTLHours := 1
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/auth/access?user_id=%s", tc.userId), nil)
			w := httptest.NewRecorder()
			tokensProviderMock := mocks.NewTokensProvider(t)
			if tc.name == "Good scenario" {
				tokensProviderMock.On("GenerateTokensPair", r.Context(), &dto.GenerateTokensPairInput{
					UserId: tc.userId,
					Addr:   r.RemoteAddr,
				}).Return(&dto.GenerateTokensPairOutput{
					AccessToken:  "random jwt string",
					RefreshToken: "random jwt string",
				}, nil).Once()
			}
			handler := handlers.NewAuthAccessHandler(mockLogger, tokensProviderMock, cookieTTLHours)
			handler.ServeHTTP(w, r)

			require.Equal(t, tc.responseCode, w.Code)
			if tc.responseError != nil {
				require.Equal(t, fmt.Sprintf("\"%s\"", tc.responseError), strings.TrimSpace(w.Body.String()))
			} else {
				var resp handlers.AuthResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				header := http.Header{}
				header.Add("Set-Cookie", w.Header().Get("Set-Cookie"))
				req := http.Response{Header: header}
				cookie := req.Cookies()[0]
				require.Equal(t, "refresh-token", cookie.Name)
				require.Equal(t, cookieTTLHours*3600, cookie.MaxAge)
			}
		})
	}
}

func TestAuthRefreshHandler(t *testing.T) {
	cookieTTLHours := 1
	cases := []struct {
		name          string
		responseCode  int
		responseError error
		responseBody  string
		cookie        string
	}{
		{
			name:          "Empty cookie",
			responseCode:  http.StatusBadRequest,
			responseError: errors.New(http.StatusText(http.StatusBadRequest)),
		},
		{
			name:          "Valid token",
			responseCode:  http.StatusOK,
			responseError: nil,
			responseBody:  "random jwt tokens",
			cookie:        "refresh-token=random_token; Path=/; Secure; HttpOnly; Expires=Tue, 20 May 2025 12:09:51 GMT;",
		},
		{
			name:          "Invalid token",
			responseCode:  http.StatusBadRequest,
			responseError: service.ErrInvalidToken,
			cookie:        "refresh-token=random_token; Path=/; Secure; HttpOnly; Expires=Tue, 20 May 2025 12:09:51 GMT;",
		},
		{
			name:          "Update from new address",
			responseCode:  http.StatusOK,
			responseError: nil,
			responseBody:  "random jwt tokens",
			cookie:        "refresh-token=random_token; Path=/; Secure; HttpOnly; Expires=Tue, 20 May 2025 12:09:51 GMT;",
		},
	}
	mockLogger := slog.New(logger.NewMockLogger())
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
			w := httptest.NewRecorder()
			tokensProviderMock := mocks.NewTokensProvider(t)
			notifierMock := mocks.NewNotifier(t)
			prevAddr := r.RemoteAddr
			if tc.cookie != "" {
				r.Header.Add("Cookie", tc.cookie)
				parsedCookie, _ := r.Cookie("refresh-token")
				if tc.name == "Update from new address" {
					notifierMock.On("Notify", r.Context(), "", "token updated from new address").
						Return(nil).
						Once()
					prevAddr = "random address"
				}
				tokensProviderMock.
					On("UpdateTokens", r.Context(), &dto.UpdateTokensInput{
						RefreshToken: parsedCookie.Value,
						Addr:         r.RemoteAddr,
					}).
					Return(&dto.UpdateTokensOutput{
						GenerateTokensPairOutput: dto.GenerateTokensPairOutput{
							AccessToken:  "random jwt string",
							RefreshToken: parsedCookie.Value,
						},
						OldRefreshTokenClaims: dto.JwtPayload{
							Addr: prevAddr,
						},
					}, tc.responseError).
					Once()
			}
			handler := handlers.NewAuthRefreshHandler(mockLogger, tokensProviderMock, notifierMock, cookieTTLHours)
			handler.ServeHTTP(w, r)
			require.Equal(t, tc.responseCode, w.Code)
			if tc.responseError != nil {
				require.Equal(t, fmt.Sprintf("\"%s\"", tc.responseError), strings.TrimSpace(w.Body.String()))
			} else {
				var resp handlers.AuthResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				header := http.Header{}
				header.Add("Set-Cookie", w.Header().Get("Set-Cookie"))
				req := http.Response{Header: header}
				cookie := req.Cookies()[0]
				require.Equal(t, "refresh-token", cookie.Name)
				require.Equal(t, cookieTTLHours*3600, cookie.MaxAge)
			}
		})
	}
}
