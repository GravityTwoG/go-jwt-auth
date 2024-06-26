package main

import (
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/models"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	dsn := os.Getenv("DSN")
	if dsn == "" {
		log.Fatal("Invalid DSN value in .env file")
	}

	db, err := database.ConnectToDB(dsn)
	if err != nil {
		log.Fatal(err)
	}

	// initial migrations
	if !db.Migrator().HasTable(&models.User{}) {
		log.Println("Creating users table")
		err = db.Migrator().CreateTable(&models.User{})
		if err != nil {
			log.Fatal(err)
		}
	}

	if !db.Migrator().HasTable(&models.RefreshToken{}) {
		log.Println("Creating refresh tokens table")
		err = db.Migrator().CreateTable(&models.RefreshToken{})
		if err != nil {
			log.Fatal(err)
		}
	}

	// future migrations
	if !db.Migrator().HasColumn(&models.RefreshToken{}, "finger_print") {
		log.Println("Adding finger print column to refresh tokens table")
		err = db.Migrator().AddColumn(&models.RefreshToken{}, "finger_print")
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Migrations complete")
}
