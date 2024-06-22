package dto

import "go-jwt-auth/internal/rest-api/entities"

type UserDTO struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}

func FromEntity(user *entities.User) *UserDTO {
	return &UserDTO{
		ID:    user.GetId(),
		Email: user.GetEmail(),
	}
}
