package database

import (
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"strings"

	"gorm.io/gorm"
)

func MapGormErrors(err error, entity string) domainerrors.ErrDomain {
	switch err {
	case gorm.ErrRecordNotFound:
		return domainerrors.NewErrEntityNotFound(
			fmt.Sprintf("%s_NOT_FOUND", strings.ToUpper(entity)),
			entity,
		)

	case gorm.ErrDuplicatedKey:
		return domainerrors.NewErrEntityAlreadyExists(
			fmt.Sprintf("%s_ALREADY_EXISTS", strings.ToUpper(entity)),
			entity,
		)

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
