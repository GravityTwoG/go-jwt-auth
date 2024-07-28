package oauth

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
)

type OAuthService interface {
	RequestConsentURL(
		ctx context.Context,
		redirectURL string,
	) string

	FetchUserEmail(
		ctx context.Context,
		code string,
		redirectURL string,
	) (string, domainerrors.ErrDomain)
}
