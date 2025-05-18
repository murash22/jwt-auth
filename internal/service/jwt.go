package service

import "github.com/golang-jwt/jwt/v5"

func VerifyJwtToken(tokenStr string, secret []byte) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return token, nil
}
