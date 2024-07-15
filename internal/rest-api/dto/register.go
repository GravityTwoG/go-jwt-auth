package dto

type RegisterDTO struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
	Password2 string `json:"password2" binding:"required"`
}

type RegisterWithGoogleDTO struct {
	Code        string `json:"code" binding:"required"`
	RedirectURL string `json:"redirectURL" binding:"required"`
}
