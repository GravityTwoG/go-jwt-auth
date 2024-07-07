package main

import (
	"go-jwt-auth/internal/rest-api/database"
	"go-jwt-auth/internal/rest-api/models"
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

	log.Println("Migrations complete")
}
