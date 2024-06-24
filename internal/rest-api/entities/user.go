package entities

import (
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	id uint

	email    string
	password string

	createdAt time.Time
	updatedAt time.Time
}

func NewUser(
	email string,
	password string,
) (*User, domainerrors.ErrDomain) {
	user := User{}

	if len(email) < 3 || len(email) > 256 {
		return nil, domainerrors.NewErrInvalidInput(
			"EMAIL_INVALID_LENGTH",
			"email must be between 3 and 256 characters",
		)
	}
	user.email = email

	err := user.ChangePassword(password)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func UserFromDB(
	id uint,
	email,
	password string,
) *User {
	return &User{
		id:       id,
		email:    email,
		password: password,
	}
}

func (u *User) GetId() uint {
	return u.id
}

func (u *User) GetEmail() string {
	return u.email
}

func (u *User) GetPassword() string {
	return u.password
}

func (u *User) ChangePassword(rawPassword string) domainerrors.ErrDomain {
	if len(rawPassword) < 8 || len(rawPassword) > 64 {
		return domainerrors.NewErrInvalidInput(
			"PASSWORD_LENGTH_INVALID",
			"password must be between 8 and 64 characters",
		)
	}

	hashedPassword, err := hashPassword(rawPassword)
	if err != nil {
		return err
	}
	u.password = hashedPassword
	return nil
}

func (u *User) ComparePassword(rawPassword string) bool {
	return comparePasswords(u.password, rawPassword)
}

func hashPassword(password string) (string, domainerrors.ErrDomain) {
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return "", domainerrors.NewErrUnknown(
			err,
		)
	}
	return string(hashedPassword), nil
}

func comparePasswords(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func (u *User) GetCreatedAt() time.Time {
	return u.createdAt
}

func (u *User) GetUpdatedAt() time.Time {
	return u.updatedAt
}
