package services_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/services"
	"go-jwt-auth/internal/rest-api/services/oauth"
)

type mockedUserRepository struct {
	mock.Mock
}

func (m *mockedUserRepository) Create(
	ctx context.Context,
	user *entities.User,
) domainerrors.ErrDomain {
	args := m.Called(ctx, user)
	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}
	return nil
}

func (m *mockedUserRepository) GetByID(
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

func (m *mockedUserRepository) GetByEmail(
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

func (m *mockedUserRepository) DeleteByID(
	ctx context.Context,
	id uint,
) domainerrors.ErrDomain {
	args := m.Called(ctx, id)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

type mockedRefreshTokenRepository struct {
	mock.Mock
}

func (m *mockedRefreshTokenRepository) Create(
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

func (m *mockedRefreshTokenRepository) Update(
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

func (m *mockedRefreshTokenRepository) GetByToken(
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

func (m *mockedRefreshTokenRepository) GetByUserID(
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

func (m *mockedRefreshTokenRepository) Delete(
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

func (m *mockedRefreshTokenRepository) DeleteByUserID(
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

func (m *mockedRefreshTokenRepository) DeleteExpired(
	ctx context.Context,
) domainerrors.ErrDomain {
	args := m.Called(ctx)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

func TestAuthService_Register(t *testing.T) {
	tests := []struct {
		name            string
		registerDTO     *dto.RegisterDTO
		mockUserCreate  func(*mock.Mock)
		mockTokenCreate func(*mock.Mock)
		expectedUser    *entities.User
		expectedTokens  *services.Tokens
		expectedErr     domainerrors.ErrDomain
	}{
		{
			name: "Successful registration",
			registerDTO: &dto.RegisterDTO{
				Email:     "test@example.com",
				Password:  "password123",
				Password2: "password123",
			},
			mockUserCreate: func(m *mock.Mock) {
				m.On("Create", mock.Anything, mock.AnythingOfType("*entities.User")).Return(nil)
			},
			mockTokenCreate: func(m *mock.Mock) {
				m.On("Create", mock.Anything, mock.AnythingOfType("*entities.RefreshToken")).Return(nil)
			},
			expectedUser: &entities.User{},
			expectedTokens: &services.Tokens{
				AccessToken:  "mocked_access_token",
				RefreshToken: entities.RefreshToken{},
			},
			expectedErr: nil,
		},
		{
			name: "Passwords don't match",
			registerDTO: &dto.RegisterDTO{
				Email:     "test@example.com",
				Password:  "password123",
				Password2: "password456",
			},
			mockUserCreate: func(m *mock.Mock) {
				// No mock call expected
			},
			mockTokenCreate: func(m *mock.Mock) {
				// No mock call expected
			},
			expectedUser:   nil,
			expectedTokens: nil,
			expectedErr: domainerrors.NewErrInvalidInput(
				"PASSWORDS_DONT_MATCH",
				"passwords don't match",
			),
		},
		{
			name: "Email already exists",
			registerDTO: &dto.RegisterDTO{
				Email:     "existing@example.com",
				Password:  "password123",
				Password2: "password123",
			},
			mockUserCreate: func(m *mock.Mock) {
				m.On("Create", mock.Anything, mock.AnythingOfType("*entities.User")).Return(
					domainerrors.NewErrEntityAlreadyExists("", ""),
				)
			},
			mockTokenCreate: func(m *mock.Mock) {
				// No mock call expected
			},
			expectedUser:   nil,
			expectedTokens: nil,
			expectedErr: domainerrors.NewErrEntityAlreadyExists(
				"EMAIL_ALREADY_EXISTS",
				"email already exists",
			),
		},
		{
			name: "Database error",
			registerDTO: &dto.RegisterDTO{
				Email:     "test@example.com",
				Password:  "password123",
				Password2: "password123",
			},
			mockUserCreate: func(m *mock.Mock) {
				m.On("Create", mock.Anything, mock.AnythingOfType("*entities.User")).Return(
					domainerrors.NewErrUnknown(nil),
				)
			},
			mockTokenCreate: func(m *mock.Mock) {
				// No mock call expected
			},
			expectedUser:   nil,
			expectedTokens: nil,
			expectedErr:    domainerrors.NewErrUnknown(nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(mockedUserRepository)
			mockRefreshTokenRepo := new(mockedRefreshTokenRepository)

			if tt.mockUserCreate != nil {
				tt.mockUserCreate(&mockUserRepo.Mock)
			}
			if tt.mockTokenCreate != nil {
				tt.mockTokenCreate(&mockRefreshTokenRepo.Mock)
			}

			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NoError(t, err)

			jwtService := services.NewJWTService(privateKey)

			googleOAuthService := oauth.NewGoogleOAuthService("", "")

			authService := services.NewAuthService(
				nil,
				mockUserRepo,
				mockRefreshTokenRepo,
				jwtService,
				3600,
				86400,
				map[string]oauth.OAuthService{
					"google": googleOAuthService,
				},
			)

			user, tokens, err := authService.Register(
				context.Background(),
				tt.registerDTO,
				"127.0.0.1",
				"Mozilla",
			)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err)
				assert.Nil(t, user)
				assert.Nil(t, tokens)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.AccessToken)
				assert.NotEmpty(t, tokens.RefreshToken.GetToken())
			}

			mockUserRepo.AssertExpectations(t)
			mockRefreshTokenRepo.AssertExpectations(t)
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	type loginTest struct {
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

	user, _ := entities.NewUser(
		"test@example.com",
		"password123",
	)
	hashedPassword := user.GetPassword()

	tests := []loginTest{
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
			mockUserRepo := new(mockedUserRepository)
			mockRefreshTokenRepository := new(mockedRefreshTokenRepository)

			mockUserRepo.
				On("GetByEmail", mock.Anything, mock.Anything).
				Return(tt.mockUser, tt.mockUserErr)

			if tt.mockUser != nil {
				mockRefreshTokenRepository.On("Create", mock.Anything, mock.AnythingOfType("*entities.RefreshToken")).Return(tt.mockRefreshCreateErr)
			}

			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.NoError(t, err)

			jwtService := services.NewJWTService(privateKey)

			googleOAuthService := oauth.NewGoogleOAuthService("", "")

			authService := services.NewAuthService(
				nil,
				mockUserRepo,
				mockRefreshTokenRepository,
				jwtService,
				3600,
				86400,
				map[string]oauth.OAuthService{
					"google": googleOAuthService,
				},
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

			mockUserRepo.AssertExpectations(t)
			mockRefreshTokenRepository.AssertExpectations(t)
		})
	}
}
