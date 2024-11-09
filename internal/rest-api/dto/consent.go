package dto

type OAuthRedirectDTO struct {
	RedirectURL  string `json:"redirectURL"`
	CodeVerifier string `json:"codeVerifier"`
}
