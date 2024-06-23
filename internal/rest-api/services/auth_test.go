package services_test

import (
	"context"

	"github.com/stretchr/testify/mock"

	domain_errors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
)

type mockUserService struct {
	mock.Mock
}

func (m *mockUserService) Login(ctx context.Context, dto *dto.LoginDTO) (*entities.User, domain_errors.ErrDomain) {
	args := m.Called(ctx, dto)

	user := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domain_errors.ErrDomain)
	}

	return user.(*entities.User), nil
}

func (m *mockUserService) GetByEmail(ctx context.Context, email string) (*entities.User, domain_errors.ErrDomain) {
	args := m.Called(ctx, email)

	user := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domain_errors.ErrDomain)
	}

	return user.(*entities.User), nil
}

type mockRefreshTokenRepository struct {
	mock.Mock
}

func (m *mockRefreshTokenRepository) Create(ctx context.Context, refreshToken *entities.RefreshToken) domain_errors.ErrDomain {
	args := m.Called(ctx, refreshToken)

	err := args.Error(0)
	if err != nil {
		return err.(domain_errors.ErrDomain)
	}

	return nil
}

func (m *mockRefreshTokenRepository) GetByToken(ctx context.Context, token string) (*entities.RefreshToken, domain_errors.ErrDomain) {
	args := m.Called(ctx, token)

	refreshToken := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domain_errors.ErrDomain)
	}

	return refreshToken.(*entities.RefreshToken), nil
}

func (m *mockRefreshTokenRepository) GetByUserEmail(ctx context.Context, email string) ([]*entities.RefreshToken, domain_errors.ErrDomain) {
	args := m.Called(ctx, email)

	refreshTokens := args.Get(0)
	err := args.Error(1)
	if err != nil {
		return nil, err.(domain_errors.ErrDomain)
	}

	return refreshTokens.([]*entities.RefreshToken), nil
}

func (m *mockRefreshTokenRepository) Delete(ctx context.Context, refreshToken *entities.RefreshToken) domain_errors.ErrDomain {
	args := m.Called(ctx, refreshToken)

	err := args.Error(0)
	if err != nil {
		return err.(domain_errors.ErrDomain)
	}

	return nil
}

func (m *mockRefreshTokenRepository) DeleteExpired(ctx context.Context) domain_errors.ErrDomain {
	args := m.Called(ctx)

	err := args.Error(0)
	if err != nil {
		return err.(domain_errors.ErrDomain)
	}

	return nil
}
