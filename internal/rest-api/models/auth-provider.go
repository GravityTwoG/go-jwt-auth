package models

import (
	"go-jwt-auth/internal/rest-api/entities"
	"time"
)

type AuthProvider struct {
	ID   uint   `gorm:"primarykey"`
	Name string `gorm:"unique;not null"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

type UserAuthProvider struct {
	Email string `gorm:"not null,default:'',uniqueIndex:idx_auth_provider_email"`

	// composite primary key (user_id, oauth_provider_id)
	UserID uint `gorm:"primarykey"`
	User   User `gorm:"onDelete:CASCADE"`

	AuthProviderID uint         `gorm:"primarykey,uniqueIndex:idx_auth_provider_email"`
	AuthProvider   AuthProvider `gorm:"onDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func UserAuthProviderFromEntity(
	entity *entities.UserAuthProvider,
) *UserAuthProvider {
	return &UserAuthProvider{
		UserID:         entity.GetUserID(),
		AuthProviderID: entity.GetAuthProviderID(),
		CreatedAt:      entity.GetCreatedAt(),
		UpdatedAt:      entity.GetUpdatedAt(),
	}
}

func UserAuthProviderFromModel(
	model *UserAuthProvider,
) *entities.UserAuthProvider {
	return entities.UserAuthProviderFromDB(
		model.Email,
		model.UserID,
		model.AuthProviderID,

		model.AuthProvider.Name,

		model.CreatedAt,
		model.UpdatedAt,
	)
}
