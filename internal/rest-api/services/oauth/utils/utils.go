package oauthutils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type PKCE struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

func GetPKCE() (*PKCE, error) {
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, err
	}

	codeChallenge := getCodeChallenge(codeVerifier)

	return &PKCE{
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}, nil
}

func getCodeChallenge(codeVerifier string) string {
	codeChallenge := sha256.Sum256([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(codeChallenge[:])
}

func generateCodeVerifier() (string, error) {
	codeVerifier := make([]byte, 32)
	_, err := rand.Read(codeVerifier)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(codeVerifier), nil
}
