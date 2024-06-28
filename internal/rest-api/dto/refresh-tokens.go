package dto

type RefreshTokensDTO struct {
	FingerPrint string `json:"fingerPrint" binding:"required"`
}
