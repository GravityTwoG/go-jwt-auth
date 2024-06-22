package entities

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	id uint

	token  string
	ttlSec int

	userId uint
	user   *User

	createdAt time.Time
	updatedAt time.Time
}

func NewRefreshToken(userId uint, ttlSec int) *RefreshToken {
	return &RefreshToken{
		userId: userId,
		token:  uuid.New().String(),
		ttlSec: ttlSec,
	}
}

func RefreshTokenFromDB(
	id uint,
	token string,
	ttlSec int,
	userId uint,
	user *User,
	createdAt time.Time,
	updatedAt time.Time,
) *RefreshToken {
	return &RefreshToken{
		id:        id,
		token:     token,
		ttlSec:    ttlSec,
		userId:    userId,
		user:      user,
		createdAt: createdAt,
		updatedAt: updatedAt,
	}
}

func (rt *RefreshToken) GetId() uint {
	return rt.id
}

func (rt *RefreshToken) GetToken() string {
	return rt.token
}

func (rt *RefreshToken) GetTtlSec() int {
	return rt.ttlSec
}

func (rt *RefreshToken) GetUserId() uint {
	return rt.userId
}

func (rt *RefreshToken) GetUser() *User {
	return rt.user
}

func (rt *RefreshToken) GetCreatedAt() time.Time {
	return rt.createdAt
}

func (rt *RefreshToken) GetUpdatedAt() time.Time {
	return rt.updatedAt
}

func (rt *RefreshToken) Expired() bool {
	expirationTime := rt.createdAt.
		Add(time.Duration(rt.ttlSec) * time.Second)

	return time.Now().After(expirationTime)
}
