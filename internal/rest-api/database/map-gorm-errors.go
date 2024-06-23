package database

import (
	"fmt"
	domain_errors "go-jwt-auth/internal/rest-api/domain-errors"

	"gorm.io/gorm"
)

func MapGormErrors(err error, entity string) domain_errors.ErrDomain {
	switch err {
	case gorm.ErrRecordNotFound:
		return domain_errors.NewErrEntityNotFound(entity)

	case gorm.ErrDuplicatedKey:
		return domain_errors.NewErrEntityAlreadyExists(entity)

	case gorm.ErrInvalidValue:
		return domain_errors.NewErrInvalidInput(
			domain_errors.InvalidInput,
			err.Error(),
		)

	default:
		fmt.Print(err)
		return domain_errors.NewErrUnknown(err)
	}
}
