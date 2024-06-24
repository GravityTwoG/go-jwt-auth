package domainerrors

import (
	"errors"
	"fmt"
)

const EntityNotFound = "ENTITY_NOT_FOUND"

const EntityAlreadyExists = "ENTITY_ALREADY_EXISTS"

const InvalidInput = "INVALID_INPUT"

const Unknown = "UNKNOWN"

type ErrDomain interface {
	Kind() string
	Code() string
	Error() string
}

type errDomain struct {
	kind string
	code string
	err  error
}

func newErr(kind string, code string, err error) ErrDomain {
	return &errDomain{
		kind: kind,
		code: code,
		err:  err,
	}
}

func (e *errDomain) Kind() string {
	return e.kind
}

func (e *errDomain) Code() string {
	return e.code
}

func (e *errDomain) Error() string {
	return e.err.Error()
}

func (e *errDomain) Unwrap() error {
	return e.err
}

func NewErrEntityNotFound(code string, entity string) ErrDomain {
	return newErr(
		EntityNotFound,
		code,
		fmt.Errorf("entity %s not found", entity),
	)
}

func NewErrEntityAlreadyExists(code string, entity string) ErrDomain {
	return newErr(
		EntityAlreadyExists,
		code,
		fmt.Errorf("entity %s already exists", entity),
	)
}

func NewErrInvalidInput(code string, err string) ErrDomain {
	return newErr(
		InvalidInput,
		code,
		errors.New(err),
	)
}

func NewErrUnknown(err error) ErrDomain {
	return newErr(Unknown, Unknown, err)
}
