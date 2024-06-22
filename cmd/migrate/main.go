package main

import (
	"go-jwt-auth/internal/rest-api/config"
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/models"
	"log"
)

func main() {
	cfg := config.MustLoadConfig()

	db, err := database.ConnectToDB(cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(&models.RefreshToken{})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Migrations complete")
}
