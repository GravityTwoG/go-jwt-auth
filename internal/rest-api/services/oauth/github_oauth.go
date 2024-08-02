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

type githubOAuthService struct {
	githubClientID     string
	githubClientSecret string
}

func NewGitHubOAuthService(
	githubClientID string,
	githubClientSecret string,
) OAuthService {
	return &githubOAuthService{
		githubClientID:     githubClientID,
		githubClientSecret: githubClientSecret,
	}
}

func (s *githubOAuthService) RequestConsentURL(
	ctx context.Context,
	redirectURL string,
) string {
	// https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#web-application-flow
	endpoint := "https://github.com/login/oauth/authorize"

	return fmt.Sprintf(
		"%s?client_id=%s&scope=user&redirect_uri=%s",
		endpoint,
		s.githubClientID,
		redirectURL,
	)
}

func (s *githubOAuthService) FetchUserEmail(
	ctx context.Context,
	code string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	accessToken, err := s.GetAccessToken(ctx, code, redirectURL)
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

func (s *githubOAuthService) GetAccessToken(
	ctx context.Context,
	code string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	endpoint := "https://github.com/login/oauth/access_token"

	client := &http.Client{}

	form := url.Values{}
	form.Add("client_id", s.githubClientID)
	form.Add("client_secret", s.githubClientSecret)
	form.Add("code", code)
	form.Add("redirect_uri", redirectURL)

	req, err := http.NewRequestWithContext(
		ctx, "POST", endpoint,
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
