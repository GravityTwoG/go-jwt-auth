package services_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/services"
)

type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) Register(
	ctx context.Context,
	dto *dto.RegisterDTO,
) (*entities.User, domainerrors.ErrDomain) {
	args := m.Called(ctx, dto)

	user := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return user.(*entities.User), nil
}

func (m *mockUserService) Login(
	ctx context.Context,
	dto *dto.LoginDTO,
) (*entities.User, domainerrors.ErrDomain) {
	args := m.Called(ctx, dto)

	user := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return user.(*entities.User), nil
}

func (m *mockUserService) GetByID(
	ctx context.Context,
	id uint,
) (*entities.User, domainerrors.ErrDomain) {
	args := m.Called(ctx, id)

	user := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return user.(*entities.User), nil
}

func (m *mockUserService) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, domainerrors.ErrDomain) {
	args := m.Called(ctx, email)

	user := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return user.(*entities.User), nil
}

type mockRefreshTokenRepository struct {
	mock.Mock
}

func (m *mockRefreshTokenRepository) Create(
	ctx context.Context,
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {
	args := m.Called(ctx, refreshToken)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

func (m *mockRefreshTokenRepository) Update(
	ctx context.Context,
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {
	args := m.Called(ctx, refreshToken)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

func (m *mockRefreshTokenRepository) GetByToken(
	ctx context.Context,
	token string,
) (*entities.RefreshToken, domainerrors.ErrDomain) {
	args := m.Called(ctx, token)

	refreshToken := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return refreshToken.(*entities.RefreshToken), nil
}

func (m *mockRefreshTokenRepository) GetByUserID(
	ctx context.Context,
	id uint,
) ([]*entities.RefreshToken, domainerrors.ErrDomain) {
	args := m.Called(ctx, id)

	refreshTokens := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return refreshTokens.([]*entities.RefreshToken), nil
}

func (m *mockRefreshTokenRepository) Delete(
	ctx context.Context,
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {
	args := m.Called(ctx, refreshToken)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

func (m *mockRefreshTokenRepository) DeleteByUserID(
	ctx context.Context,
	userID uint,
) domainerrors.ErrDomain {
	args := m.Called(ctx, userID)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

func (m *mockRefreshTokenRepository) DeleteExpired(
	ctx context.Context,
) domainerrors.ErrDomain {
	args := m.Called(ctx)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

type authLoginTest struct {
	name                 string
	loginDTO             *dto.LoginDTO
	ip                   string
	userAgent            string
	mockUser             *entities.User
	mockUserErr          domainerrors.ErrDomain
	mockRefreshCreateErr domainerrors.ErrDomain
	expectedUser         *entities.User
	expectedTokens       bool
	expectedErr          domainerrors.ErrDomain
}

func TestAuthService_Login(t *testing.T) {
	user, _ := entities.NewUser(
		"test@example.com",
		"password123",
	)
	hashedPassword := user.GetPassword()

	tests := []authLoginTest{
		{
			name: "Should successfully log in user and return tokens when credentials are valid",
			loginDTO: &dto.LoginDTO{
				Email:    "test@example.com",
				Password: "password123",
			},
			ip:        "127.0.0.1",
			userAgent: "Mozilla/5.0",

			mockUser: entities.UserFromDB(
				1,
				"test@example.com",
				hashedPassword,
			),
			mockUserErr:          nil,
			mockRefreshCreateErr: nil,

			expectedUser: entities.UserFromDB(
				1,
				"test@example.com",
				hashedPassword,
			),
			expectedTokens: true,
			expectedErr:    nil,
		},

		{
			name: "Should return an error when user provides invalid credentials",
			loginDTO: &dto.LoginDTO{
				Email:    "test@example.com",
				Password: "wrong_password",
			},
			ip:        "127.0.0.1",
			userAgent: "Mozilla/5.0",

			mockUser: nil,
			mockUserErr: domainerrors.NewErrInvalidInput(
				"INCORRECT_EMAIL_OR_PASSWORD",
				"Incorrect email or password",
			),
			mockRefreshCreateErr: nil,

			expectedUser:   nil,
			expectedTokens: false,
			expectedErr: domainerrors.NewErrInvalidInput(
				"INCORRECT_EMAIL_OR_PASSWORD",
				"Incorrect email or password",
			),
		},

		{
			name: "Should return an error when a database error occurs during login",
			loginDTO: &dto.LoginDTO{
				Email:    "test@example.com",
				Password: "password123",
			},
			ip:        "127.0.0.1",
			userAgent: "Mozilla/5.0",

			mockUser:             nil,
			mockUserErr:          domainerrors.NewErrUnknown(nil),
			mockRefreshCreateErr: nil,

			expectedUser:   nil,
			expectedTokens: false,
			expectedErr:    domainerrors.NewErrUnknown(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserService := new(mockUserService)
			mockRefreshTokenRepository := new(mockRefreshTokenRepository)

			mockUserService.On("Login", mock.Anything, tt.loginDTO).Return(tt.mockUser, tt.mockUserErr)
			if tt.mockUser != nil {
				mockRefreshTokenRepository.On("Create", mock.Anything, mock.AnythingOfType("*entities.RefreshToken")).Return(tt.mockRefreshCreateErr)
			}

			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatal(err)
			}

			authService := services.NewAuthService(
				nil,
				mockUserService,
				mockRefreshTokenRepository,
				privateKey,
				3600,
				86400,
				"",
				"",
			)

			user, tokens, err := authService.Login(context.Background(), tt.loginDTO, tt.ip, tt.userAgent)

			if tt.expectedUser != nil {
				assert.Equal(t, tt.expectedUser.GetID(), user.GetID())
				assert.Equal(t, tt.expectedUser.GetEmail(), user.GetEmail())
			} else {
				assert.Nil(t, user)
			}

			if tt.expectedTokens {
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.AccessToken)
				assert.NotEmpty(t, tokens.RefreshToken.GetToken())
			} else {
				assert.Nil(t, tokens)
			}

			assert.Equal(t, tt.expectedErr, err)

			mockUserService.AssertExpectations(t)
			mockRefreshTokenRepository.AssertExpectations(t)
		})
	}
}
