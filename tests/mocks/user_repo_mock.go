package mocks

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/entities"

	"github.com/stretchr/testify/mock"
)

type MockedUserRepository struct {
	mock.Mock
}

func (m *MockedUserRepository) Create(
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

func (m *MockedUserRepository) GetByID(
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

func (m *MockedUserRepository) GetByEmail(
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

func (m *MockedUserRepository) DeleteByID(
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
