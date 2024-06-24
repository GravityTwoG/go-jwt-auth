package ginutils

import (
	"github.com/gin-gonic/gin"
)

func DecodeJSON[T any](ctx *gin.Context) (T, error) {
	var dto T
	err := ctx.ShouldBindJSON(&dto)
	if err != nil {
		return dto, err
	}
	return dto, nil
}
