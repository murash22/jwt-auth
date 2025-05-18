package config

import (
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Db                  Database
	Server              Server
	JwtSecret           string `env:"JWT_SECRET"`
	JwtAccessTTLMinutes int    `env:"JWT_ACCESS_TTL"`
	JwtRefreshTTLHours  int    `env:"JWT_REFRESH_TTL"`
	CookiesTTLHours     int    `env:"COOKIES_TTL"`
	WebhookUrl          string `env:"WEBHOOK_URL"`
}

type Database struct {
	Host     string `env:"DB_HOST"`
	Username string `env:"DB_USER"`
	Password string `env:"DB_PASSWORD"`
	Name     string `env:"DB_NAME"`
}

type Server struct {
	Host string `env:"SERVER_HOSTNAME"`
}

func MustLoad(configPath string) *Config {
	cfg := &Config{}
	err := cleanenv.ReadConfig(configPath, cfg)
	if err != nil {
		panic(err)
	}
	return cfg
}

func (d *Database) Url() string {
	return fmt.Sprintf("postgresql://%s:%s@%s:5432/%s", d.Username, d.Password, d.Host, d.Name)
}
