package dto

type LoginDTO struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required"`
	FingerPrint string `json:"fingerPrint" binding:"required"`
}

type LoginWithOAuthDTO struct {
	Code         string `json:"code" binding:"required"`
	CodeVerifier string `json:"codeVerifier" binding:"required"`
	DeviceID     string `json:"deviceId"`
	FingerPrint  string `json:"fingerPrint" binding:"required"`
	RedirectURL  string `json:"redirectURL" binding:"required"`
}

type LoginResponseDTO struct {
	AccessToken  string  `json:"accessToken"`
	RefreshToken string  `json:"refreshToken"`
	User         UserDTO `json:"user"`
}
