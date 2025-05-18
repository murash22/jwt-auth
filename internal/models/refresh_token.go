package models

import "time"

type RefreshToken struct {
	Uuid      string    `json:"uuid"`
	UserId    string    `json:"user_id"`
	Value     string    `json:"value"`
	IpAddr    string    `json:"ip_addr"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
