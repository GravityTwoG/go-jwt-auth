package entities

import "time"

type UserAuthProvider struct {
	userID         uint
	authProviderID uint

	name string

	createdAt time.Time
	updatedAt time.Time
}

func NewUserAuthProvider(
	userID uint,
	providerName string,
) *UserAuthProvider {
	return &UserAuthProvider{
		userID:         userID,
		authProviderID: 0,
		name:           providerName,
	}
}

func UserAuthProviderFromDB(
	userID uint,
	authProviderID uint,

	name string,

	createdAt time.Time,
	updatedAt time.Time,
) *UserAuthProvider {
	return &UserAuthProvider{
		userID:         userID,
		authProviderID: authProviderID,
		name:           name,

		createdAt: createdAt,
		updatedAt: updatedAt,
	}
}

func (u *UserAuthProvider) GetUserID() uint {
	return u.userID
}

func (u *UserAuthProvider) GetAuthProviderID() uint {
	return u.authProviderID
}

func (u *UserAuthProvider) GetName() string {
	return u.name
}

func (u *UserAuthProvider) GetCreatedAt() time.Time {
	return u.createdAt
}

func (u *UserAuthProvider) GetUpdatedAt() time.Time {
	return u.updatedAt
}
