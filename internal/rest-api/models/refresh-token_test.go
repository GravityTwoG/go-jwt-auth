package models_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/models"
)

func TestRefreshTokenFromEntity(t *testing.T) {
	t.Run("should return model from entity", func(t *testing.T) {
		t.Parallel()

		refreshToken := entities.NewRefreshToken(
			"token",
			1,
			3600,
			"127.0.0.1",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36",
			"",
		)

		expectedModel := &models.RefreshToken{
			ID: 0,

			Token:  refreshToken.GetToken(),
			TTLsec: 3600,

			UserID: 1,
			User:   models.User{},

			IP:        "127.0.0.1",
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36",

			CreatedAt: time.Time{},
			UpdatedAt: time.Time{},
		}

		actualModel := models.RefreshTokenFromEntity(refreshToken)
		assert.Equal(t, expectedModel, actualModel)
	})

	t.Run("should return model with user from entity", func(t *testing.T) {
		t.Parallel()

		refreshToken := entities.RefreshTokenFromDB(
			0,

			"token",
			3600,

			1,
			entities.UserFromDB(
				1,
				"email",
				"password",
			),

			"127.0.0.1",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36",
			"",

			time.Time{},
			time.Time{},
		)

		expectedModel := &models.RefreshToken{
			ID: 0,

			Token:  "token",
			TTLsec: 3600,

			UserID: 1,
			User: models.User{
				ID:       1,
				Email:    "email",
				Password: "password",
			},

			IP:        "127.0.0.1",
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36",

			CreatedAt: time.Time{},
			UpdatedAt: time.Time{},
		}

		actualModel := models.RefreshTokenFromEntity(refreshToken)
		assert.Equal(t, expectedModel, actualModel)
	})
}
