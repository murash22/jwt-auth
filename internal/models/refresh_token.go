package models

import "time"

type RefreshToken struct {
	UserId    string    `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
}
