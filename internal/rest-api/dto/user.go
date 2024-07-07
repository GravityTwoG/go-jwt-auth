package dto

import "go-jwt-auth/internal/rest-api/entities"

type UserDTO struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}

func UserFromEntity(user *entities.User) *UserDTO {
	return &UserDTO{
		ID:    user.GetID(),
		Email: user.GetEmail(),
	}
}
