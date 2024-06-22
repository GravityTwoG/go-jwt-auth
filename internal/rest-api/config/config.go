// config/config.go

package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	JWTSecretKey        string
	JWTExpirationMillis int64
	Port                string
	DSN                 string
}

func MustLoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	config := &Config{}

	config.JWTSecretKey = os.Getenv("JWT_SECRET_KEY")
	if config.JWTSecretKey == "" {
		log.Fatal("JWT_SECRET_KEY not set in .env file")
	}

	jwtExpirationMillisStr := os.Getenv("JWT_EXPIRATION_MILLIS")
	config.JWTExpirationMillis, err = strconv.ParseInt(jwtExpirationMillisStr, 10, 64)
	if err != nil {
		log.Fatal("Invalid JWT_EXPIRATION_MILLIS value in .env file")
	}

	config.Port = os.Getenv("PORT")
	if config.Port == "" {
		config.Port = "8080" // Default port if not specified
	}

	config.DSN = os.Getenv("DSN")
	if config.DSN == "" {
		log.Fatal("Invalid DSN value in .env file")
	}

	return config
}
