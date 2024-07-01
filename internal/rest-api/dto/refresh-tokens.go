package dto

type RefreshTokensDTO struct {
	FingerPrint string `json:"fingerPrint" binding:"required"`
}

type RefreshTokensResponseDTO struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}
