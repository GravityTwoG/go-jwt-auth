package mocks

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/entities"

	"github.com/stretchr/testify/mock"
)

type MockedUserAuthProviderRepository struct {
	mock.Mock
}

func (m *MockedUserAuthProviderRepository) Create(
	ctx context.Context,
	userID uint,
	providerName string,
) domainerrors.ErrDomain {
	args := m.Called(ctx, userID, providerName)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}

func (m *MockedUserAuthProviderRepository) GetByUserID(
	ctx context.Context,
	userID uint,
) ([]*entities.UserAuthProvider, domainerrors.ErrDomain) {
	args := m.Called(ctx, userID)

	userAuthProvider := args.Get(0)
	err := args.Error(1)

	if err != nil {
		return nil, err.(domainerrors.ErrDomain)
	}

	return userAuthProvider.([]*entities.UserAuthProvider), nil
}

func (m *MockedUserAuthProviderRepository) Delete(
	ctx context.Context,
	userAuthProvider *entities.UserAuthProvider,
) domainerrors.ErrDomain {
	args := m.Called(ctx, userAuthProvider)

	err := args.Error(0)
	if err != nil {
		return err.(domainerrors.ErrDomain)
	}

	return nil
}
