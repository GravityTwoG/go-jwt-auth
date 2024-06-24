package services_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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
) domain_errors.ErrDomain {
	args := m.Called(ctx, user)
	err := args.Error(0)
	if err != nil {
		return err.(domain_errors.ErrDomain)
	}
	return nil
}

func (m *mockedUserRepository) GetByID(
	ctx context.Context,
	id uint,
) (*entities.User, domain_errors.ErrDomain) {
	args := m.Called(ctx, id)

	user := args.Get(0)
	err := args.Error(1)

	if err != nil {
		return nil, err.(domain_errors.ErrDomain)
	}

	return user.(*entities.User), nil
}

func (m *mockedUserRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, domain_errors.ErrDomain) {

	args := m.Called(ctx, email)

	user := args.Get(0)
	err := args.Error(1)

	if err != nil {
		return nil, err.(domain_errors.ErrDomain)
	}

	return user.(*entities.User), nil
}

type registerTest struct {
	name            string
	registerDTO     *dto.RegisterDTO
	mockSetup       func(*mockedUserRepository)
	expectedErr     bool
	expectedErrCode string
}

func TestUserService_Register(t *testing.T) {
	tests := []registerTest{
		{
			name: "should return error if passwords don't match",
			registerDTO: &dto.RegisterDTO{
				Email:     "w8vCq@example.com",
				Password:  "password",
				Password2: "not-the-same",
			},
			mockSetup:       func(*mockedUserRepository) {},
			expectedErr:     true,
			expectedErrCode: "PASSWORDS_DONT_MATCH",
		},
		{
			name: "should return user if registration is successful",
			registerDTO: &dto.RegisterDTO{
				Email:     "w8vCq@example.com",
				Password:  "password",
				Password2: "password",
			},
			mockSetup: func(m *mockedUserRepository) {
				m.On("Create", mock.Anything, mock.Anything).Return(nil)
			},
			expectedErr: false,
		},
		{
			name: "should return error if user already exists",
			registerDTO: &dto.RegisterDTO{
				Email:     "w8vCq@example.com",
				Password:  "password",
				Password2: "password",
			},
			mockSetup: func(m *mockedUserRepository) {
				m.On("Create", mock.Anything, mock.Anything).Return(domain_errors.NewErrEntityAlreadyExists("user"))
			},
			expectedErr:     true,
			expectedErrCode: "EMAIL_ALREADY_EXISTS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			userRepoMock := &mockedUserRepository{}
			tt.mockSetup(userRepoMock)

			userService := services.NewUserService(userRepoMock)
			user, err := userService.Register(context.Background(), tt.registerDTO)

			if tt.expectedErr {
				assert.NotNil(t, err)
				assert.Nil(t, user)
				if tt.expectedErrCode != "" {
					assert.Contains(t, err.Code(), tt.expectedErrCode)
				}
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, user)
			}
		})
	}
}

type loginTest struct {
	name            string
	loginDTO        *dto.LoginDTO
	mockSetup       func(*mockedUserRepository)
	expectedErr     bool
	expectedErrCode string
}

func TestUserService_Login(t *testing.T) {
	tests := []loginTest{
		{
			name: "should return error if user doesn't exist",
			loginDTO: &dto.LoginDTO{
				Email:    "w8vCq@example.com",
				Password: "password",
			},
			mockSetup: func(m *mockedUserRepository) {
				m.On("GetByEmail", mock.Anything, mock.Anything).Return(nil, domain_errors.NewErrEntityNotFound("user"))
			},
			expectedErr:     true,
			expectedErrCode: "INCORRECT_EMAIL_OR_PASSWORD",
		},
		{
			name: "should return error if password is incorrect",
			loginDTO: &dto.LoginDTO{
				Email:    "w8vCq@example.com",
				Password: "password",
			},
			mockSetup: func(m *mockedUserRepository) {
				userFromDB := entities.UserFromDB(1, "w8vCq@example.com", "another-password")
				m.On("GetByEmail", mock.Anything, mock.Anything).Return(userFromDB, nil)
			},
			expectedErr:     true,
			expectedErrCode: "INCORRECT_EMAIL_OR_PASSWORD",
		},
		{
			name: "should return user if login is successful",
			loginDTO: &dto.LoginDTO{
				Email:    "w8vCq@example.com",
				Password: "password",
			},
			mockSetup: func(m *mockedUserRepository) {
				userFromDB := entities.UserFromDB(1, "w8vCq@example.com", "")
				userFromDB.ChangePassword("password")
				m.On("GetByEmail", mock.Anything, mock.Anything).Return(userFromDB, nil)
			},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			userRepoMock := &mockedUserRepository{}
			tt.mockSetup(userRepoMock)

			userService := services.NewUserService(userRepoMock)
			user, err := userService.Login(context.Background(), tt.loginDTO)

			if tt.expectedErr {
				assert.NotNil(t, err)
				assert.Nil(t, user)
				if tt.expectedErrCode != "" {
					assert.Contains(t, err.Code(), tt.expectedErrCode)
				}
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, user)
			}
		})
	}
}
