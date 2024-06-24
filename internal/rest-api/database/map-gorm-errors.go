package database

import (
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"

	"gorm.io/gorm"
)

func MapGormErrors(err error, entity string) domainerrors.ErrDomain {
	switch err {
	case gorm.ErrRecordNotFound:
		return domainerrors.NewErrEntityNotFound(entity)

	case gorm.ErrDuplicatedKey:
		return domainerrors.NewErrEntityAlreadyExists(entity)

	case gorm.ErrInvalidValue:
		return domainerrors.NewErrInvalidInput(
			domainerrors.InvalidInput,
			err.Error(),
		)

	default:
		fmt.Print(err)
		return domainerrors.NewErrUnknown(err)
	}
}
