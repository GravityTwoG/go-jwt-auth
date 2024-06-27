package models

import (
	"go-jwt-auth/internal/rest-api/entities"
	"time"
)

type User struct {
	ID uint `gorm:"primarykey"`

	Email    string `gorm:"unique;not null"`
	Password string `gorm:"not null"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func UserFromEntity(user *entities.User) *User {
	return &User{
		ID:       user.GetID(),
		Email:    user.GetEmail(),
		Password: user.GetPassword(),
	}
}

func UserFromModel(userModel *User) *entities.User {
	return entities.UserFromDB(
		userModel.ID,
		userModel.Email,
		userModel.Password,
	)
}
