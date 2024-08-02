package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type GoogleTokenClaims struct {
	Email string `json:"email"`
}

type googleOAuthService struct {
	googleClientID     string
	googleClientSecret string
}

func NewGoogleOAuthService(googleClientID string,
	googleClientSecret string) OAuthService {
	return &googleOAuthService{
		googleClientID:     googleClientID,
		googleClientSecret: googleClientSecret,
	}
}

func (s *googleOAuthService) RequestConsentURL(
	ctx context.Context,
	redirectURL string,
) string {
	// https://developers.google.com/identity/protocols/oauth2/web-server#httprest
	endpoint := "https://accounts.google.com/o/oauth2/v2/auth"

	responseType := "code"

	// https://developers.google.com/identity/protocols/oauth2/scopes#oauth2
	scope := "https://www.googleapis.com/auth/userinfo.email"

	return fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s",
		endpoint,
		s.googleClientID,
		redirectURL,
		responseType,
		scope,
	)
}

func (s *googleOAuthService) FetchUserEmail(
	ctx context.Context,
	code string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	endpoint := "https://www.googleapis.com/oauth2/v4/token"

	client := &http.Client{}

	form := url.Values{}
	form.Add("code", code)
	form.Add("client_id", s.googleClientID)
	form.Add("client_secret", s.googleClientSecret)
	form.Add("redirect_uri", redirectURL)
	form.Add("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(
		ctx, "POST", endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))

	resp, err := client.Do(req)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", domainerrors.NewErrUnknown(
			fmt.Errorf("unexpected status code: %d", resp.StatusCode),
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	var dto struct {
		IDToken string `json:"id_token"`
	}

	err = json.Unmarshal(body, &dto)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	email, err := ParseEmailFromJWT(dto.IDToken, "email")
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return email, nil
}
