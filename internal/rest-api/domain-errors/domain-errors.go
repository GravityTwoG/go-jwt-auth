package domain_errors

import "fmt"

type ErrDomain struct {
	Err  error
	Code string
}

func (e *ErrDomain) Error() string {
	return e.Err.Error()
}

type ErrEntityNotFound struct {
	ErrDomain
}

func NewErrEntityNotFound(entity string) *ErrEntityNotFound {
	return &ErrEntityNotFound{ErrDomain{
		Err:  fmt.Errorf("entity %s not found", entity),
		Code: "ENTITY_NOT_FOUND",
	}}
}

type ErrEntityAlreadyExists struct {
	ErrDomain
}

func NewErrEntityAlreadyExists(entity string) *ErrEntityAlreadyExists {
	return &ErrEntityAlreadyExists{ErrDomain{
		Err:  fmt.Errorf("entity %s already exists", entity),
		Code: "ENTITY_ALREADY_EXISTS",
	}}
}

type ErrInvalidInput struct {
	ErrDomain
}

func NewErrInvalidInput(err string) *ErrInvalidInput {
	return &ErrInvalidInput{ErrDomain{
		Err:  fmt.Errorf("invalid input: %s", err),
		Code: "INVALID_INPUT",
	}}
}

type ErrUnknown struct {
	ErrDomain
}

func NewErrUnknown(err error) *ErrUnknown {
	return &ErrUnknown{ErrDomain{
		Err:  err,
		Code: "UNKNOWN",
	}}
}
