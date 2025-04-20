package service

import (
	"auth_service/internal/config"
	"auth_service/internal/dto"
	"auth_service/internal/models"
	"auth_service/internal/repo"
	"auth_service/internal/storage"
	"context"
	"encoding/base64"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"strings"
	"time"
)

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrVerifyingToken = errors.New("error verifying token")
)

type authService struct {
	repo                  repo.RefreshTokenRepo
	logger                *slog.Logger
	jwtSecret             []byte
	accessTokenTTLMinutes int64
	refreshTokenTTLHours  int64
}

func NewAuthService(logger *slog.Logger, cfg *config.Config, repo repo.RefreshTokenRepo) *authService {
	return &authService{
		repo:                  repo,
		logger:                logger,
		jwtSecret:             []byte(cfg.JwtSecret),
		accessTokenTTLMinutes: int64(cfg.JwtAccessTTLMinutes),
		refreshTokenTTLHours:  int64(cfg.JwtRefreshTTLHours),
	}
}

func (s *authService) GenerateTokensPair(ctx context.Context, inp *dto.GenerateTokensPairInput) (*dto.GenerateTokensPairOutput, error) {
	tokensPair, err := s.newTokensPair(inp)
	if err != nil {
		s.logger.Error("error generating tokens pair", "err", err)
		return nil, err
	}
	err = s.repo.DeleteRefreshTokenByUserId(ctx, inp.UserId)
	if err != nil && !errors.Is(err, storage.ErrNoSucRecord) {
		s.logger.Error("error deleting refresh token", "err", err)
		return nil, err
	}
	err = s.saveRefreshToken(ctx, inp.UserId, tokensPair.RefreshToken)
	if err != nil {
		s.logger.Error("error saving refresh token", "err", err)
		return nil, err
	}
	return &dto.GenerateTokensPairOutput{
		AccessToken:  tokensPair.AccessToken,
		RefreshToken: tokensPair.RefreshToken,
	}, nil
}

func (s *authService) UpdateTokens(ctx context.Context, inp *dto.UpdateTokensInput) (*dto.UpdateTokensOutput, error) {
	token, err := s.verifyToken(inp.RefreshToken)
	if err != nil {
		s.logger.Error("error verifying refresh token", "err", err)
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		s.logger.Error("failed to parse token claims", "err", err, "claims", claims)
		return nil, ErrInvalidToken
	}
	userId := claims["sub"].(string)
	oldToken, err := s.repo.GetRefreshTokenByUserId(ctx, userId)
	if err != nil {
		s.logger.Error("error getting old refresh token", "err", err, "userId", userId)
		if errors.Is(err, storage.ErrNoSucRecord) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	oldTokenSignatureHash := []byte(oldToken.TokenHash)
	decodedSign, err := s.getDecodedSignature(inp.RefreshToken)
	err = bcrypt.CompareHashAndPassword(oldTokenSignatureHash, decodedSign)
	if err != nil { // was provided old token
		s.logger.Error("tokens hash are not equal", "err", err, "userId", userId)
		return nil, ErrInvalidToken
	}
	if err = s.repo.DeleteRefreshTokenByUserId(ctx, userId); err != nil { // invalidate old refresh token
		s.logger.Error("error deleting old refresh token", "err", err, "userId", userId)
		return nil, err
	}
	tokensPair, err := s.newTokensPair(&dto.GenerateTokensPairInput{
		UserId: userId,
		Addr:   inp.Addr,
	})
	if err != nil {
		s.logger.Error("error generating tokens pair", "err", err)
		return nil, err
	}
	if err = s.saveRefreshToken(ctx, userId, tokensPair.RefreshToken); err != nil {
		s.logger.Error("error saving refresh token", "err", err, "userId", userId)
		return nil, err
	}
	expirationTime, _ := claims.GetExpirationTime()
	return &dto.UpdateTokensOutput{
		dto.GenerateTokensPairOutput{
			AccessToken:  tokensPair.AccessToken,
			RefreshToken: tokensPair.RefreshToken,
		},
		dto.JwtPayload{
			Subject: claims["sub"].(string),
			Exp:     expirationTime.Unix(),
			Addr:    claims["addr"].(string),
		},
	}, nil
}

func (s *authService) verifyToken(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		s.logger.Error("error verifying token", "err", err)
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed), errors.Is(err, jwt.ErrTokenSignatureInvalid),
			errors.Is(err, jwt.ErrTokenExpired), errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, ErrInvalidToken
		default:
			return nil, ErrVerifyingToken
		}
	}
	return token, nil
}

func (s *authService) getDecodedSignature(token string) ([]byte, error) {
	signatureEncoded := strings.SplitN(token, ".", 3)[2]
	return base64.RawURLEncoding.DecodeString(signatureEncoded)
}

func (s *authService) saveRefreshToken(ctx context.Context, userId string, token string) error {
	sign, err := s.getDecodedSignature(token)
	if err != nil {
		return err
	}
	tokenHash, err := bcrypt.GenerateFromPassword(sign, 10)
	if err != nil {
		return err
	}

	err = s.repo.InsertRefreshToken(ctx, &models.RefreshToken{
		TokenHash: string(tokenHash),
		UserId:    userId,
	})
	return err
}

func (s *authService) newTokensPair(inp *dto.GenerateTokensPairInput) (*dto.GenerateTokensPairOutput, error) {
	now := time.Now()
	p := &dto.JwtPayload{
		Subject: inp.UserId,
		Addr:    inp.Addr,
		Exp:     now.Add(time.Duration(s.accessTokenTTLMinutes) * time.Minute).Unix(),
	}
	accessToken, err := s.newSignedToken(p)
	if err != nil {
		return nil, err
	}
	p.Exp = now.Add(time.Duration(s.refreshTokenTTLHours) * time.Hour).Unix()
	refreshToken, err := s.newSignedToken(p)
	if err != nil {
		return nil, err
	}
	return &dto.GenerateTokensPairOutput{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) newSignedToken(payload *dto.JwtPayload) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub":  payload.Subject,
		"exp":  payload.Exp,
		"addr": payload.Addr,
	})
	return token.SignedString(s.jwtSecret)
}
