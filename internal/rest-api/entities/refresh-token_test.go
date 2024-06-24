package entities_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go-jwt-auth/internal/rest-api/entities"
)

func TestRefreshTokenExpiry(t *testing.T) {
	t.Run("should return true if token expired", func(t *testing.T) {
		t.Parallel()

		min30 := 1800
		token := entities.RefreshTokenFromDB(
			0,

			"token",
			min30,

			1,
			&entities.User{},

			"127.0.0.1",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36",

			time.Now().Add(-1*time.Hour),
			time.Now().Add(-1*time.Hour),
		)

		assert.True(t, token.Expired())
	})

	t.Run("should return false if token not expired", func(t *testing.T) {
		t.Parallel()

		hour2 := 7200
		token := entities.RefreshTokenFromDB(
			0,

			"token",
			hour2,

			1,
			&entities.User{},

			"127.0.0.1",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.142.86 Safari/537.36",

			time.Now().Add(-1*time.Hour),
			time.Now().Add(-1*time.Hour),
		)

		assert.False(t, token.Expired())
	})
}
