package dto

type RegisterDTO struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required"`
	Password2 string `json:"password2" binding:"required"`
}
