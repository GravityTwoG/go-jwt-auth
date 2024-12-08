package ginutils

import (
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"net/http"

	"github.com/gin-gonic/gin"
)

func DecodeJSON[T any](ctx *gin.Context) (T, domainerrors.ErrDomain) {
	var dto T
	err := ctx.ShouldBindJSON(&dto)
	if err != nil {
		return dto, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		)
	}
	return dto, nil
}

func WriteError(
	c *gin.Context,
	err domainerrors.ErrDomain,
) {
	status := http.StatusInternalServerError

	switch {
	case err.Kind() == domainerrors.EntityNotFound:
		status = http.StatusNotFound
	case err.Kind() == domainerrors.EntityAlreadyExists:
		status = http.StatusConflict
	case err.Kind() == domainerrors.InvalidInput:
		status = http.StatusBadRequest
	}

	WriteErrorWithStatus(c, status, err)
}

func WriteErrorWithStatus(
	c *gin.Context,
	status int,
	err domainerrors.ErrDomain,
) {
	c.JSON(status, &dto.ErrorResponseDTO{
		Kind:  err.Kind(),
		Code:  err.Code(),
		Error: err.Error(),
	})
}
