package entities

import (
	"time"
)

type RefreshToken struct {
	id uint

	token  string
	ttlSec int

	userId uint
	user   *User

	ip          string
	userAgent   string
	fingerPrint string

	createdAt time.Time
	updatedAt time.Time
}

func NewRefreshToken(
	token string,
	userId uint,
	ttlSec int,
	ip string,
	userAgent string,
	fingerPrint string,
) *RefreshToken {
	return &RefreshToken{
		token:  token,
		ttlSec: ttlSec,

		userId: userId,

		ip:        ip,
		userAgent: userAgent,

		fingerPrint: fingerPrint,
	}
}

func RefreshTokenFromDB(
	id uint,
	token string,
	ttlSec int,
	userId uint,
	user *User,
	ip string,
	userAgent string,
	fingerPrint string,
	createdAt time.Time,
	updatedAt time.Time,
) *RefreshToken {
	return &RefreshToken{
		id: id,

		token:  token,
		ttlSec: ttlSec,

		userId: userId,
		user:   user,

		ip:          ip,
		userAgent:   userAgent,
		fingerPrint: fingerPrint,

		createdAt: createdAt,
		updatedAt: updatedAt,
	}
}

func (rt *RefreshToken) GetID() uint {
	return rt.id
}

func (rt *RefreshToken) GetToken() string {
	return rt.token
}

func (rt *RefreshToken) SetToken(token string) {
	rt.token = token
}

func (rt *RefreshToken) GetTTLSec() int {
	return rt.ttlSec
}

func (rt *RefreshToken) GetUserID() uint {
	return rt.userId
}

func (rt *RefreshToken) GetUser() *User {
	return rt.user
}

func (rt *RefreshToken) GetIP() string {
	return rt.ip
}

func (rt *RefreshToken) GetUserAgent() string {
	return rt.userAgent
}

func (rt *RefreshToken) GetFingerPrint() string {
	return rt.fingerPrint
}

func (rt *RefreshToken) GetCreatedAt() time.Time {
	return rt.createdAt
}

func (rt *RefreshToken) GetUpdatedAt() time.Time {
	return rt.updatedAt
}
