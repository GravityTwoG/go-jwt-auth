package models

import (
	"go-jwt-auth/internal/rest-api/entities"
	"time"
)

type RefreshToken struct {
	ID uint `gorm:"primarykey"`

	Token  string `gorm:"unique;not null"`
	TTLsec int    `gorm:"not null"`

	UserID uint `gorm:"not null"`
	User   User `gorm:"onDelete:CASCADE"`

	IP        string
	UserAgent string

	CreatedAt time.Time
	UpdatedAt time.Time
}

func RefreshTokenFromEntity(refreshToken *entities.RefreshToken) *RefreshToken {
	var user User
	if refreshToken.GetUser() != nil {
		user = *UserFromEntity(refreshToken.GetUser())
	}

	return &RefreshToken{
		ID: refreshToken.GetId(),

		Token:  refreshToken.GetToken(),
		TTLsec: refreshToken.GetTtlSec(),

		UserID: refreshToken.GetUserId(),
		User:   user,

		IP:        refreshToken.GetIP(),
		UserAgent: refreshToken.GetUserAgent(),

		CreatedAt: refreshToken.GetCreatedAt(),
		UpdatedAt: refreshToken.GetUpdatedAt(),
	}
}

func RefreshTokenFromModel(refreshTokenModel *RefreshToken) *entities.RefreshToken {
	return entities.RefreshTokenFromDB(
		refreshTokenModel.ID,

		refreshTokenModel.Token,
		refreshTokenModel.TTLsec,

		refreshTokenModel.UserID,
		entities.UserFromDB(
			refreshTokenModel.UserID,
			refreshTokenModel.User.Email,
			refreshTokenModel.User.Password,
		),

		refreshTokenModel.IP,
		refreshTokenModel.UserAgent,

		refreshTokenModel.CreatedAt,
		refreshTokenModel.UpdatedAt,
	)
}
