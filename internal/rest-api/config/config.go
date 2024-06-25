// config/config.go

package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	JWTSecretKey       string
	JWTAccessTTLsec    int
	RefreshTokenTTLsec int

	Port string

	AllowedOrigins []string

	DSN string
}

func MustLoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	config := &Config{}

	config.JWTSecretKey = os.Getenv("JWT_SECRET_KEY")
	if config.JWTSecretKey == "" {
		log.Fatal("JWT_SECRET_KEY not set in .env file")
	}

	config.JWTAccessTTLsec, err = strconv.Atoi(os.Getenv("JWT_ACCESS_TTL_SEC"))
	if err != nil {
		log.Fatal("Invalid JWT_ACCESS_TTL_SEC value in .env file")
	}

	config.RefreshTokenTTLsec, err = strconv.Atoi(os.Getenv("REFRESH_TOKEN_TTL_SEC"))
	if err != nil {
		log.Fatal("Invalid REFRESH_TOKEN_TTL_SEC value in .env file")
	}

	config.AllowedOrigins = []string{}
	origins := os.Getenv("ALLOWED_ORIGINS")
	if origins != "" {
		for _, host := range strings.Split(origins, ",") {
			config.AllowedOrigins = append(
				config.AllowedOrigins,
				strings.TrimSpace(host),
			)
		}
	}

	config.DSN = os.Getenv("DSN")
	if config.DSN == "" {
		log.Fatal("Invalid DSN value in .env file")
	}

	config.Port = os.Getenv("PORT")
	if config.Port == "" {
		config.Port = "8080" // Default port if not specified
	}

	log.Println("Config loaded")

	return config
}
