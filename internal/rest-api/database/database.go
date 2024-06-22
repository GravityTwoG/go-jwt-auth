package database

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectToDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		TranslateError: true,
	})

	return db, err
}
