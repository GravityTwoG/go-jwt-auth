package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockedTRManager struct {
	mock.Mock
}

func (m *MockedTRManager) Do(
	ctx context.Context,
	fn func(ctx context.Context) error,
) error {
	return fn(ctx)
}
