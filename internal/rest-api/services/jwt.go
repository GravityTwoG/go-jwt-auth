package services

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/entities"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type TokenClaims struct {
	ID    uint
	Email string
}

type GoogleTokenClaims struct {
	Email string `json:"email"`
}

func newJWT(
	user *entities.User,
	ttlSec int,
	privateKey *rsa.PrivateKey,
) (string, domainerrors.ErrDomain) {

	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	// for uniqueness
	claims["uuid"] = uuid.New().String()
	claims["id"] = user.GetID()
	claims["email"] = user.GetEmail()
	claims["exp"] = time.
		Now().
		Add(time.Duration(ttlSec) * time.Second).
		Unix()

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return tokenString, nil
}

func VerifyAndParseJWT(
	tokenString string, publicKey *rsa.PublicKey,
) (*TokenClaims, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return publicKey, nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		return nil, errors.New("token-expired")
	}

	return &TokenClaims{
		ID:    uint(claims["id"].(float64)),
		Email: claims["email"].(string),
	}, nil
}

func ParseRSAKey(
	privateKeyBase64 string,
) (*rsa.PrivateKey, error) {

	// Decode private key
	privateKeyPEM, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to parse PEM block containing private key")
	}

	var privateKey *rsa.PrivateKey

	// Try parsing as PKCS1
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		// If PKCS1 fails, try PKCS8
		privatePKCS8Key, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		privateKey, ok = privatePKCS8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
	}

	return privateKey, nil
}

// just parse the token payload
func ParseGoogleJWT(tokenString string) (*GoogleTokenClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, fmt.Errorf("invalid token")
	}

	return &GoogleTokenClaims{
		Email: claims["email"].(string),
	}, nil
}
