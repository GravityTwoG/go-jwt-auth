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

// https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#web-application-flow
const githubAuthorizeURL = "https://github.com/login/oauth/authorize"
const githubExchangeURL = "https://github.com/login/oauth/access_token"

type githubOAuthService struct {
	clientID     string
	clientSecret string
}

func NewGitHubOAuthService(
	clientID string,
	clientSecret string,
) OAuthService {
	return &githubOAuthService{
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

func (s *githubOAuthService) RequestConsentURL(
	ctx context.Context,
	redirectURL string,
) (*OAuthConsentDTO, domainerrors.ErrDomain) {
	pkce, err := oauthutils.GetPKCE()
	if err != nil {
		return nil, domainerrors.NewErrUnknown(err)
	}

	redirectURL = fmt.Sprintf(
		"%s?client_id=%s&scope=user&redirect_uri=%s&state=&code_challenge=%s&code_challenge_method=%s",
		githubAuthorizeURL,
		s.clientID,
		redirectURL,
		pkce.CodeChallenge,
		pkce.CodeChallengeMethod,
	)

	return &OAuthConsentDTO{
		RedirectURL:  redirectURL,
		CodeVerifier: pkce.CodeVerifier,
	}, nil
}

func (s *githubOAuthService) FetchUserEmail(
	ctx context.Context,
	code string,
	codeVerifier string,
	deviceID string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	accessToken, err := s.getAccessToken(ctx, code, codeVerifier, redirectURL)
	if err != nil {
		return "", err
	}

	endpoint := "https://api.github.com/user/emails"

	client := &http.Client{}

	req, httpErr := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if httpErr != nil {
		return "", domainerrors.NewErrUnknown(httpErr)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, httpErr := client.Do(req)
	if httpErr != nil {
		return "", domainerrors.NewErrUnknown(httpErr)
	}

	body, httpErr := io.ReadAll(resp.Body)
	if httpErr != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	httpErr = json.Unmarshal(body, &emails)
	if httpErr != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	primaryEmail := ""
	for _, email := range emails {
		if email.Primary {
			primaryEmail = email.Email
			break
		}
	}
	if primaryEmail == "" {
		return "", domainerrors.NewErrUnknown(fmt.Errorf("no primary email"))
	}

	return primaryEmail, nil
}

func (s *githubOAuthService) getAccessToken(
	ctx context.Context,
	code string,
	codeVerifier string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	client := &http.Client{}

	form := url.Values{}
	form.Add("client_id", s.clientID)
	form.Add("client_secret", s.clientSecret)
	form.Add("code", code)
	form.Add("code_verifier", codeVerifier)
	form.Add("redirect_uri", redirectURL)

	req, err := http.NewRequestWithContext(
		ctx, "POST", githubExchangeURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Accept", "application/json")

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
		AccessToken string `json:"access_token"`
	}

	err = json.Unmarshal(body, &dto)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return dto.AccessToken, nil
}
