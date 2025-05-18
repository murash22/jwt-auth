package service

import (
	"auth_service/internal/config"
	"auth_service/internal/dto"
	"auth_service/internal/models"
	"auth_service/internal/repo"
	"auth_service/internal/storage"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrChangedUserAgent = errors.New("changed user agent")
)

type authService struct {
	repo                  repo.RefreshTokenRepo
	logger                *slog.Logger
	jwtSecret             []byte
	accessTokenTTLMinutes int64
	refreshTokenTTLHours  int64
	base64Encoding        *base64.Encoding
	webhookAddr           string
}

func NewAuthService(logger *slog.Logger, cfg *config.Config, repo repo.RefreshTokenRepo) *authService {
	return &authService{
		repo:                  repo,
		logger:                logger,
		jwtSecret:             []byte(cfg.JwtSecret),
		accessTokenTTLMinutes: int64(cfg.JwtAccessTTLMinutes),
		refreshTokenTTLHours:  int64(cfg.JwtRefreshTTLHours),
		base64Encoding:        base64.StdEncoding,
	}
}

func (s *authService) GenerateTokensPair(ctx context.Context, inp *dto.GenerateTokensPairInput) (*dto.GenerateTokensPairOutput, error) {
	err := s.repo.DeleteRefreshTokenByUserId(ctx, inp.UserId) // if user tries to generate new pairs token when he already logged in => deleting old refresh-token
	if err != nil && !errors.Is(err, storage.ErrNoSucRecord) {
		s.logger.Error("error deleting refresh token", "err", err)
		return nil, err
	}
	tokensPair, err := s.newTokensPair(ctx, inp)
	if err != nil {
		s.logger.Error("error generating tokens pair", "err", err)
		return nil, err
	}
	return &dto.GenerateTokensPairOutput{
		TokensPair: *tokensPair,
	}, nil
}

func (s *authService) UpdateTokens(ctx context.Context, inp *dto.UpdateTokensInput) (*dto.UpdateTokensOutput, error) {
	accessToken, err := VerifyJwtToken(inp.AccessToken, s.jwtSecret)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) { // считаю, что даже если истек срок действия access_token, мы можем обновить refresh_token,
		s.logger.Error("error while updating tokens: error verifying token", "err", err) // так как у refresh_token свое время жизни
		return nil, ErrInvalidToken
	}
	rawRefToken, err := s.base64Encoding.DecodeString(inp.RefreshToken)
	rawRefTokenSplit := strings.Split(string(rawRefToken), ".")
	if err != nil || len(rawRefTokenSplit) != 2 {
		s.logger.Error("error while parsing refresh token", "err", err, "token", string(rawRefToken))
		return nil, ErrInvalidToken
	}
	refTokenId, refTokenHash := rawRefTokenSplit[0], rawRefTokenSplit[1]
	refToken, err := s.repo.GetRefreshTokenByUuid(ctx, refTokenId)
	if err != nil {
		s.logger.Error("error getting refresh token", "err", err)
		return nil, ErrInvalidToken
	}
	err = bcrypt.CompareHashAndPassword([]byte(refToken.Value), []byte(refTokenHash))
	if err != nil {
		s.logger.Error("error comparing token hash", "err", err)
		return nil, ErrInvalidToken
	}
	userId, err := accessToken.Claims.GetSubject()
	if err != nil || refToken.ExpiresAt.Before(time.Now()) || refToken.UserId != userId { // if refresh-token expired, or
		s.logger.Error("bad token pair", "err", err) // access and refresh tokens dont belong to each other
		return nil, ErrInvalidToken
	}
	err = s.repo.DeleteRefreshTokenByUuid(ctx, refTokenId) // удаляем refresh_token из бд
	if err != nil {
		s.logger.Error("error deleting refresh token", "refTokenId", refTokenId, "err", err)
		return nil, err
	}
	if refToken.UserAgent != inp.UserAgent { // уже деавторизовали при удалении токена из бд
		s.logger.Error("trying to update tokens with new UserAgent", "refTokenId", refTokenId, "newUserAgent", inp.UserAgent)
		return nil, ErrChangedUserAgent
	}
	tokensPair, err := s.newTokensPair(ctx, &dto.GenerateTokensPairInput{
		UserId:    userId,
		Addr:      inp.Addr,
		UserAgent: inp.UserAgent,
	})
	if err != nil {
		s.logger.Error("error generating tokens pair", "err", err)
		return nil, err
	}
	if refToken.IpAddr != inp.Addr {
		s.logger.Info("refreshing token from new address", "oldAddr", refToken.IpAddr, "newAddr", inp.Addr)
		if err = s.notifyAboutIpChange(ctx, userId, refToken.IpAddr, inp.Addr); err != nil {
			s.logger.Error("error notifying about ip change", "err", err)
		}
	}
	return &dto.UpdateTokensOutput{
		TokensPair: *tokensPair,
	}, nil
}

func (s *authService) Logout(ctx context.Context, userId string) error {
	err := s.repo.DeleteRefreshTokenByUserId(ctx, userId)
	if err != nil {
		s.logger.Error("error while logging out: error deleting refresh token", "err", err)
		if errors.Is(err, storage.ErrNoSucRecord) {
			return ErrInvalidToken
		}
		return err
	}
	return nil
}

func (s *authService) saveRefreshToken(ctx context.Context, token *models.RefreshToken) (string, error) {
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(token.Value), 10)
	if err != nil {
		return "", err
	}
	now := time.Now()
	tokenId := uuid.New().String()
	err = s.repo.InsertRefreshToken(ctx, &models.RefreshToken{
		Uuid:      tokenId,
		UserId:    token.UserId,
		Value:     string(tokenHash),
		IpAddr:    token.IpAddr,
		UserAgent: token.UserAgent,
		ExpiresAt: now.Add(time.Duration(s.refreshTokenTTLHours) * time.Hour),
	})
	return tokenId, err
}

func (s *authService) newTokensPair(ctx context.Context, inp *dto.GenerateTokensPairInput) (*dto.TokensPair, error) {
	now := time.Now()
	p := &dto.JwtPayload{
		Subject: inp.UserId,
		Exp:     now.Add(time.Duration(s.accessTokenTTLMinutes) * time.Minute).Unix(),
	}
	accessToken, err := s.newAccessToken(p)
	if err != nil {
		return nil, err
	}
	refreshTokenRaw, err := s.newRefreshToken() // random bytes
	if err != nil {
		return nil, err
	}

	refToken := string(refreshTokenRaw)
	refTokenId, err := s.saveRefreshToken(ctx, &models.RefreshToken{
		UserId:    inp.UserId,
		Value:     refToken,
		IpAddr:    inp.Addr,
		UserAgent: inp.UserAgent,
	})
	if err != nil {
		return nil, err
	}

	return &dto.TokensPair{
		AccessToken:  accessToken,
		RefreshToken: s.base64Encoding.EncodeToString([]byte(refTokenId + "." + refToken)),
	}, nil
}

func (s *authService) newRefreshToken() ([]byte, error) {
	refreshTokenRaw := make([]byte, 64)
	_, err := rand.Read(refreshTokenRaw)
	if err != nil {
		return nil, err
	}
	return refreshTokenRaw, nil
}

func (s *authService) newAccessToken(payload *dto.JwtPayload) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": payload.Subject,
		"exp": payload.Exp,
	})
	return token.SignedString(s.jwtSecret)
}

func (s *authService) notifyAboutIpChange(ctx context.Context, userId, oldIp, newIp string) error {
	s.logger.Info("trying to notify webhook about ip change", "oldIp", oldIp, "newIp", newIp)
	body := make(map[string]string)
	body["user_id"] = userId
	body["old_ip_addr"] = oldIp
	body["new_ip_addr"] = newIp
	bodyRaw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookAddr, bytes.NewReader(bodyRaw))
	if err != nil {
		s.logger.Error("error creating new http request", "err", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	_, err = client.Do(req)
	return err
}
