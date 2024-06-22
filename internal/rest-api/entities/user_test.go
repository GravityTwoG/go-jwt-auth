package entities_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"go-jwt-auth/internal/rest-api/entities"
)

func TestComparePassword(t *testing.T) {
	t.Run("should return true if password is correct", func(t *testing.T) {
		t.Parallel()

		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword(
			[]byte(password),
			bcrypt.DefaultCost,
		)

		user := entities.UserFromDB(
			0,
			"email",
			string(hashedPassword),
		)

		assert.True(t, user.ComparePassword(password))
	})

	t.Run("should return false if password is incorrect", func(t *testing.T) {
		t.Parallel()

		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword(
			[]byte(password),
			bcrypt.DefaultCost,
		)

		user := entities.UserFromDB(
			0,
			"email",
			string(hashedPassword),
		)

		assert.False(t, user.ComparePassword("wrongPassword"))
	})
}

func TestChangePassword(t *testing.T) {
	t.Run("should return error if password is too short", func(t *testing.T) {
		t.Parallel()

		user := entities.UserFromDB(
			0,
			"email",
			"password",
		)

		err := user.ChangePassword("short")
		assert.NotNil(t, err)
	})

	t.Run("should return error if password is too long", func(t *testing.T) {
		t.Parallel()

		user := entities.UserFromDB(
			0,
			"email",
			"password",
		)

		veryLongPassword := "veryLongPassword"
		for i := 0; i < 10; i++ {
			veryLongPassword = veryLongPassword + veryLongPassword
		}

		err := user.ChangePassword(veryLongPassword)
		assert.NotNil(t, err)
	})

	t.Run("should return nil if password is valid", func(t *testing.T) {
		t.Parallel()

		user := entities.UserFromDB(
			0,
			"email",
			"password",
		)

		err := user.ChangePassword("newPassword")
		assert.Nil(t, err)
	})

	t.Run("should require new password", func(t *testing.T) {
		t.Parallel()

		user := entities.UserFromDB(
			0,
			"email",
			"password",
		)

		err := user.ChangePassword("newPassword")
		assert.Nil(t, err)
		assert.False(t, user.ComparePassword("password"))
		assert.True(t, user.ComparePassword("newPassword"))
	})
}
