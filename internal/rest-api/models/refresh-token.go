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

	IP          string `gorm:"not null"`
	UserAgent   string `gorm:"not null"`
	FingerPrint string `gorm:"not null;default:''"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

func RefreshTokenFromEntity(refreshToken *entities.RefreshToken) *RefreshToken {
	var user User
	if refreshToken.GetUser() != nil {
		user = *UserFromEntity(refreshToken.GetUser())
	}

	return &RefreshToken{
		ID: refreshToken.GetID(),

		Token:  refreshToken.GetToken(),
		TTLsec: refreshToken.GetTTLSec(),

		UserID: refreshToken.GetUserID(),
		User:   user,

		IP:          refreshToken.GetIP(),
		UserAgent:   refreshToken.GetUserAgent(),
		FingerPrint: refreshToken.GetFingerPrint(),

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
		refreshTokenModel.FingerPrint,

		refreshTokenModel.CreatedAt,
		refreshTokenModel.UpdatedAt,
	)
}
