package services

import (
	"errors"
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

func newJWT(
	user *entities.User,
	ttlSec int,
	secretKey []byte,
) (string, domainerrors.ErrDomain) {

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	// for uniqueness
	claims["uuid"] = uuid.New().String()
	claims["id"] = user.GetID()
	claims["email"] = user.GetEmail()
	claims["exp"] = time.
		Now().
		Add(time.Duration(ttlSec) * time.Second).
		Unix()

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return tokenString, nil
}

func ParseJWT(tokenString string, jwtSecretKey []byte) (*TokenClaims, error) {
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what we expect
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecretKey, nil
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
