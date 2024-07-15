package middlewares

import (
	"crypto/rsa"
	"errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/services"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var ErrAuthHeaderMissing = errors.New("header 'Authorization' is missing")
var ErrAuthHeaderInvalid = errors.New(
	"authorization header format must be 'Bearer {token}'",
)

// Checks if provided bearer token is valid.
// Sets email to the context if everything is valid.
func AuthMiddleware(jwtPublicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := parseBearerToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		claims, err := services.VerifyAndParseJWT(tokenString, jwtPublicKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Set user to the context
		userDTO := dto.UserDTO{
			ID:    claims.ID,
			Email: claims.Email,
		}
		c.Set("user", userDTO)
		c.Next()
	}
}

func ExtractUser(c *gin.Context) *dto.UserDTO {
	maybeUser, ok := c.Get("user")
	if !ok {
		return nil
	}

	user := maybeUser.(dto.UserDTO)
	return &user
}

// Checks if provided bearer token is expired or it is not provided.
// If it is provided and valid, aborts the request
// If it is provided and is not valid, aborts the request
func AnonymousMiddleware(jwtPublicKey *rsa.PublicKey) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := parseBearerToken(c)
		if err != nil && errors.Is(err, ErrAuthHeaderMissing) {
			c.Next()
			return
		}

		_, err = services.VerifyAndParseJWT(tokenString, jwtPublicKey)
		// If the token is not valid or it is not provided, continue
		if err != nil {
			c.Next()
			return
		}

		// if the token is valid and provided, abort the request
		c.JSON(http.StatusForbidden, gin.H{"error": "Already logged in"})
		c.Abort()
	}
}

func parseBearerToken(c *gin.Context) (string, error) {

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", ErrAuthHeaderMissing
	}

	// Check if the Authorization header has the correct format
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", ErrAuthHeaderInvalid
	}

	return parts[1], nil
}
