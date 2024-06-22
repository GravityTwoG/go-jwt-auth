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
			1,
			3600,
		)

		expectedModel := &models.RefreshToken{
			ID:        0,
			Token:     refreshToken.GetToken(),
			TTLsec:    3600,
			UserID:    1,
			User:      models.User{},
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
			time.Time{},
			time.Time{},
		)

		expectedModel := &models.RefreshToken{
			ID:     0,
			Token:  "token",
			TTLsec: 3600,
			UserID: 1,
			User: models.User{
				ID:       1,
				Email:    "email",
				Password: "password",
			},
			CreatedAt: time.Time{},
			UpdatedAt: time.Time{},
		}

		actualModel := models.RefreshTokenFromEntity(refreshToken)
		assert.Equal(t, expectedModel, actualModel)
	})
}
