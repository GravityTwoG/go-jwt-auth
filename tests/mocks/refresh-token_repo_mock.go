package mocks

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/entities"

	"github.com/stretchr/testify/mock"
)

type MockedRefreshTokenRepository struct {
	mock.Mock
}

func (m *MockedRefreshTokenRepository) Create(
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

func (m *MockedRefreshTokenRepository) Update(
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

func (m *MockedRefreshTokenRepository) GetByToken(
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

func (m *MockedRefreshTokenRepository) GetByUserID(
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

func (m *MockedRefreshTokenRepository) Delete(
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

func (m *MockedRefreshTokenRepository) DeleteByUserID(
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

func (m *MockedRefreshTokenRepository) DeleteExpired(
	ctx context.Context,
) domainerrors.ErrDomain {
	args := m.Called(ctx)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}
