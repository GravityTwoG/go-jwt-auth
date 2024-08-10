package dto

type ConnectOAuthDTO struct {
	Code        string `json:"code" binding:"required"`
	RedirectURL string `json:"redirectURL" binding:"required"`
}

type ConnectOAuthResponseDTO struct {
	Message string `json:"message"`
}
