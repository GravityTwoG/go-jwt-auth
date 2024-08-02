package config

import (
	"log"
	"strings"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	JWTPrivateKey      string `env:"JWT_PRIVATE_KEY" env-required:"true"`
	AccessTokenTTLsec  int    `env:"ACCESS_TOKEN_TTL_SEC" env-required:"true"`
	RefreshTokenTTLsec int    `env:"REFRESH_TOKEN_TTL_SEC" env-required:"true"`

	Port string `env:"PORT" env-default:"8080"`

	AllowedOrigins stringList `env:"ALLOWED_ORIGINS"`

	Domain string `env:"DOMAIN" env-required:"true"`

	DSN string `env:"DSN" env-required:"true"`

	GoogleClientID     string `env:"GOOGLE_CLIENT_ID" env-required:"true"`
	GoogleClientSecret string `env:"GOOGLE_CLIENT_SECRET" env-required:"true"`

	GitHubClientID     string `env:"GITHUB_CLIENT_ID" env-required:"true"`
	GitHubClientSecret string `env:"GITHUB_CLIENT_SECRET" env-required:"true"`
}

func MustLoadConfig() *Config {
	config := &Config{}

	err := cleanenv.ReadConfig("../.env", config)
	if err != nil {
		log.Println("Error reading config from file: ", err)
	}

	err = cleanenv.ReadEnv(config)
	if err != nil {
		log.Fatal("Error reading config from env: ", err)
	}

	err = cleanenv.UpdateEnv(config)
	if err != nil {
		log.Fatal("Error updating config: ", err)
	}

	log.Println("Config loaded")

	return config
}

type stringList []string

func (l *stringList) SetValue(origins string) error {
	allowedOrigins := []string{}

	if origins != "" {
		for _, host := range strings.Split(origins, ",") {
			allowedOrigins = append(
				allowedOrigins,
				strings.TrimSpace(host),
			)
		}
	}

	*l = allowedOrigins
	return nil
}

func (l *stringList) Update(origins string) error {
	return l.SetValue(origins)
}
