package models

import (
	"time"
)

type RefreshToken struct {
	ID uint `gorm:"primarykey"`

	Token  string `gorm:"unique;not null"`
	TTLsec int    `gorm:"not null"`

	UserID uint `gorm:"not null"`
	User   User `gorm:"onDelete:CASCADE"`

	CreatedAt time.Time
	UpdatedAt time.Time
}
