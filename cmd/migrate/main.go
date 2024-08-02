package main

import (
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/models"
	"go-jwt-auth/internal/rest-api/services"
	"log"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	DSN string `env:"DSN"`
}

func main() {
	cfg := Config{}
	err := cleanenv.ReadConfig("../../.env", &cfg)
	if err != nil {
		log.Println("Error reading config from file: ", err)
	}

	err = cleanenv.ReadEnv(&cfg)
	if err != nil {
		log.Fatal("Error reading config from env: ", err)
	}

	err = cleanenv.UpdateEnv(&cfg)
	if err != nil {
		log.Fatal("Error updating config: ", err)
	}

	db, err := database.ConnectToDB(cfg.DSN)
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

	if !db.Migrator().HasTable(&models.AuthProvider{}) {
		log.Println("Creating auth providers table")
		err = db.Migrator().CreateTable(&models.AuthProvider{})
		if err != nil {
			log.Fatal(err)
		}

		err = db.Create(&models.AuthProvider{
			Name: services.LocalAuthProvider,
		}).Error
		if err != nil {
			log.Fatalf("Error creating local auth provider: %v", err)
		}

		err = db.Create(&models.AuthProvider{
			Name: "google",
		}).Error
		if err != nil {
			log.Fatalf("Error creating google auth provider: %v", err)
		}
	}

	if !db.Migrator().HasTable(&models.UserAuthProvider{}) {
		log.Println("Creating user auth providers table")
		err = db.Migrator().CreateTable(&models.UserAuthProvider{})
		if err != nil {
			log.Fatal(err)
		}

		localAuthProvider := models.AuthProvider{}
		err = db.
			Model(&models.AuthProvider{}).
			Where(&models.AuthProvider{Name: services.LocalAuthProvider}).
			First(&localAuthProvider).Error
		if err != nil {
			log.Fatalf("Error getting local auth provider: %v", err)
		}

		// create local auth provider for all users
		err = db.Raw("INSERT INTO user_auth_providers (user_id, auth_provider_id) SELECT id, ? FROM users", localAuthProvider.ID).Error
		if err != nil {
			log.Fatalf("Error creating local auth provider for all users: %v", err)
		}
	}

	log.Println("Migrations complete")
}
