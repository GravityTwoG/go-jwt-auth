package dto

type ConnectOAuthDTO struct {
	Code         string `json:"code" binding:"required"`
	CodeVerifier string `json:"codeVerifier" binding:"required"`
	DeviceID     string `json:"deviceId"`
	RedirectURL  string `json:"redirectURL" binding:"required"`
}

type ConnectOAuthResponseDTO struct {
	Message string `json:"message"`
}
