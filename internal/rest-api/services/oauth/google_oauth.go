package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	oauthutils "go-jwt-auth/internal/rest-api/services/oauth/utils"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// https://developers.google.com/identity/protocols/oauth2/web-server#httprest
const googleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
const googleExchangeURL = "https://www.googleapis.com/oauth2/v4/token"

type GoogleTokenClaims struct {
	Email string `json:"email"`
}

type googleOAuthService struct {
	clientID     string
	clientSecret string
}

func NewGoogleOAuthService(googleClientID string,
	googleClientSecret string) OAuthService {
	return &googleOAuthService{
		clientID:     googleClientID,
		clientSecret: googleClientSecret,
	}
}

func (s *googleOAuthService) RequestConsentURL(
	ctx context.Context,
	redirectURL string,
) (*OAuthConsentDTO, domainerrors.ErrDomain) {

	pkce, err := oauthutils.GetPKCE()
	if err != nil {
		return nil, domainerrors.NewErrUnknown(err)
	}

	responseType := "code"

	// https://developers.google.com/identity/protocols/oauth2/scopes#oauth2
	scope := "https://www.googleapis.com/auth/userinfo.email"

	redirectURL = fmt.Sprintf(
		"%s?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&code_challenge=%s&code_challenge_method=%s",
		googleAuthorizeURL,
		s.clientID,
		redirectURL,
		responseType,
		scope,
		pkce.CodeChallenge,
		pkce.CodeChallengeMethod,
	)

	return &OAuthConsentDTO{
		RedirectURL:  redirectURL,
		CodeVerifier: pkce.CodeVerifier,
	}, nil
}

func (s *googleOAuthService) FetchUserEmail(
	ctx context.Context,
	code string,
	codeVerifier string,
	deviceID string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	client := &http.Client{}

	form := url.Values{}
	form.Add("code", code)
	form.Add("code_verifier", codeVerifier)
	form.Add("client_id", s.clientID)
	form.Add("client_secret", s.clientSecret)
	form.Add("redirect_uri", redirectURL)
	form.Add("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(
		ctx, "POST", googleExchangeURL,
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
