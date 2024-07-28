package dto

type RegisterDTO struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required"`
	Password2   string `json:"password2" binding:"required"`
	FingerPrint string `json:"fingerPrint" binding:"required"`
}

type OAuthRedirectDTO struct {
	RedirectURL string `json:"redirectURL"`
}

type RegisterWithOAuthDTO struct {
	Code        string `json:"code" binding:"required"`
	RedirectURL string `json:"redirectURL" binding:"required"`
	FingerPrint string `json:"fingerPrint" binding:"required"`
}

type RegisterResponseDTO struct {
	AccessToken  string  `json:"accessToken"`
	RefreshToken string  `json:"refreshToken"`
	User         UserDTO `json:"user"`
}
