package services_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"

	domain_errors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/services"
)

type mockedUserRepository struct {
	mock.Mock
}

func (m *mockedUserRepository) Create(
	ctx context.Context,
	user *entities.User,
) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockedUserRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*entities.User), args.Error(1)
}

func TestUserService_Register(t *testing.T) {
	t.Run("should return error if passwords don't match", func(t *testing.T) {
		t.Parallel()

		userService := services.NewUserService(nil)
		user, err := userService.Register(
			context.Background(),
			&dto.RegisterDTO{
				Email:     "w8vCq@example.com",
				Password:  "password",
				Password2: "not-the-same",
			},
		)
		assert.NotNil(t, err)
		assert.Nil(t, user)
	})

	t.Run("should return user if registration is successful", func(t *testing.T) {
		t.Parallel()

		userRepoMock := &mockedUserRepository{}
		userRepoMock.
			On("Create", mock.Anything, mock.Anything).
			Return(nil)

		userService := services.NewUserService(userRepoMock)
		user, err := userService.Register(
			context.Background(),
			&dto.RegisterDTO{
				Email:     "w8vCq@example.com",
				Password:  "password",
				Password2: "password",
			},
		)
		assert.Nil(t, err)
		assert.NotNil(t, user)
	})

	t.Run("should return error if user already exists", func(t *testing.T) {
		t.Parallel()

		userRepoMock := &mockedUserRepository{}
		userRepoMock.
			On("Create", mock.Anything, mock.Anything).
			Return(domain_errors.NewErrEntityAlreadyExists("user"))

		userService := services.NewUserService(userRepoMock)
		user, err := userService.Register(
			context.Background(),
			&dto.RegisterDTO{
				Email:     "w8vCq@example.com",
				Password:  "password",
				Password2: "password",
			},
		)
		assert.NotNil(t, err)
		assert.Nil(t, user)
	})
}

func TestUserService_Login(t *testing.T) {
	t.Run("should return error if user doesn't exist", func(t *testing.T) {
		t.Parallel()

		var userNil *entities.User

		userRepoMock := &mockedUserRepository{}
		userRepoMock.
			On("GetByEmail", mock.Anything, mock.Anything).
			Return(userNil, gorm.ErrRecordNotFound)

		userService := services.NewUserService(userRepoMock)
		user, err := userService.Login(
			context.Background(),
			&dto.LoginDTO{
				Email:    "w8vCq@example.com",
				Password: "password",
			},
		)
		assert.NotNil(t, err)
		assert.Nil(t, user)
	})

	t.Run("should return error if password is incorrect", func(t *testing.T) {
		t.Parallel()

		userFromDB := entities.UserFromDB(
			1,
			"w8vCq@example.com",
			"another-password",
		)

		userRepoMock := &mockedUserRepository{}
		userRepoMock.
			On("GetByEmail", mock.Anything, mock.Anything).
			Return(userFromDB, nil)

		userService := services.NewUserService(userRepoMock)
		user, err := userService.Login(
			context.Background(),
			&dto.LoginDTO{
				Email:    "w8vCq@example.com",
				Password: "password",
			},
		)
		assert.NotNil(t, err)
		assert.Nil(t, user)
	})
}