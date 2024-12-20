package oauth

import (
	"context"
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"

	"github.com/golang-jwt/jwt/v4"
)

type OAuthConsentDTO struct {
	RedirectURL  string
	CodeVerifier string
}

type OAuthService interface {
	RequestConsentURL(
		ctx context.Context,
		redirectURL string,
	) (*OAuthConsentDTO, domainerrors.ErrDomain)

	FetchUserEmail(
		ctx context.Context,
		code string,
		codeVerifier string,
		deviceID string,
		redirectURL string,
	) (string, domainerrors.ErrDomain)
}

func ParseEmailFromJWT(tokenString string, emailField string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return "", fmt.Errorf("invalid token")
	}

	email, ok := claims[emailField].(string)

	if !ok {
		return "", fmt.Errorf("invalid token")
	}

	return email, nil
}
