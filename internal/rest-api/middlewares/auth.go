package middlewares

import (
	"errors"
	"go-jwt-auth/internal/rest-api/dto"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var ErrAuthHeaderMissing = errors.New("header 'Authorization' is missing")
var ErrAuthHeaderInvalid = errors.New(
	"authorization header format must be 'Bearer {token}'",
)

// Checks if provided bearer token is valid.
// Sets email to the context if everything is valid.
func AuthMiddleware(jwtSecretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := parseBearerToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		token, err := parseJWT(tokenString, jwtSecretKey)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Check if the token has expired
			if float64(time.Now().Unix()) > claims["exp"].(float64) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
				c.Abort()
				return
			}

			// Set user to the context
			userDTO := dto.UserDTO{
				ID:    uint(claims["id"].(float64)),
				Email: claims["email"].(string),
			}
			c.Set("user", userDTO)
			c.Next()
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
	}
}

func ExtractUser(c *gin.Context) *dto.UserDTO {
	user, ok := c.Get("user")
	if !ok {
		return nil
	}
	return user.(*dto.UserDTO)
}

// Checks if provided bearer token is expired or it is not provided.
// If it is provided and valid, aborts the request
// If it is provided and is not valid, aborts the request
func AnonymousMiddleware(jwtSecretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := parseBearerToken(c)
		if err != nil && errors.Is(err, ErrAuthHeaderMissing) {
			c.Next()
			return
		}

		_, err = parseJWT(tokenString, jwtSecretKey)
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

func parseJWT(tokenString string, jwtSecretKey []byte) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecretKey, nil
	})

	return token, err
}
