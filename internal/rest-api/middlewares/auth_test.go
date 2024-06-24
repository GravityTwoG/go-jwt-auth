package middlewares_test

import (
	"go-jwt-auth/internal/rest-api/middlewares"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func generateJWT(secretKey []byte, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func TestAuthMiddleware(t *testing.T) {
	tests := []struct {
		name string

		claims jwt.MapClaims
		token  string

		setupRouter func(*gin.Engine)

		expectedStatus int
	}{
		{
			name: "should allow access with valid token",
			claims: jwt.MapClaims{
				"exp":   float64(time.Now().Add(time.Hour).Unix()),
				"email": "test@example.com",
				"id":    uint(123),
			},

			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AuthMiddleware([]byte("secret")))
				router.GET("/test", func(c *gin.Context) {
					user := middlewares.ExtractUser(c)
					assert.NotNil(t, user)
					assert.Equal(t, "test@example.com", user.Email)
					assert.Equal(t, uint(123), user.ID)
					c.Status(http.StatusOK)
				})
			},
			expectedStatus: http.StatusOK,
		},

		{
			name:  "should return unauthorized for invalid token",
			token: "invalidtoken",

			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AuthMiddleware([]byte("secret")))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})
			},

			expectedStatus: http.StatusUnauthorized,
		},

		{
			name:  "should return unauthorized for token with invalid secret",
			token: "invalidtoken",

			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AuthMiddleware([]byte("othersecret")))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})
			},

			expectedStatus: http.StatusUnauthorized,
		},

		{
			name: "should return unauthorized for expired token",
			claims: jwt.MapClaims{
				"exp":   float64(time.Now().Add(-time.Hour).Unix()),
				"email": "test@example.com",
				"id":    uint(123),
			},
			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AuthMiddleware([]byte("secret")))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})
			},

			expectedStatus: http.StatusUnauthorized,
		},
	}

	secretKey := []byte("secret")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			gin.SetMode(gin.TestMode)

			var tokenString string
			if tt.token != "" {
				tokenString = tt.token
			} else if tt.claims != nil {
				var err error
				tokenString, err = generateJWT(secretKey, tt.claims)
				assert.NoError(t, err)
			}

			router := gin.New()
			tt.setupRouter(router)

			req, _ := http.NewRequest("GET", "/test", nil)
			if tokenString != "" {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestAnonymousMiddleware(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		token  string

		setupRouter func(*gin.Engine)

		expectedStatus int
	}{
		{
			name: "should forbid access with valid token",
			claims: jwt.MapClaims{
				"exp":   float64(time.Now().Add(time.Hour).Unix()),
				"email": "test@example.com",
				"id":    uint(123),
			},

			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AnonymousMiddleware([]byte("secret")))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})
			},

			expectedStatus: http.StatusForbidden,
		},
		{
			name: "should allow access without token",

			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AnonymousMiddleware([]byte("secret")))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})
			},

			expectedStatus: http.StatusOK,
		},
		{
			name:  "should allow access with invalid token",
			token: "invalidtoken",

			setupRouter: func(router *gin.Engine) {
				router.Use(middlewares.AnonymousMiddleware([]byte("secret")))
				router.GET("/test", func(c *gin.Context) {
					c.Status(http.StatusOK)
				})
			},

			expectedStatus: http.StatusOK,
		},
	}

	secretKey := []byte("secret")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			gin.SetMode(gin.TestMode)

			var tokenString string
			if tt.token != "" {
				tokenString = tt.token
			} else if tt.claims != nil {
				var err error
				tokenString, err = generateJWT(secretKey, tt.claims)
				assert.NoError(t, err)
			}

			router := gin.New()
			tt.setupRouter(router)

			req, _ := http.NewRequest("GET", "/test", nil)
			if tokenString != "" {
				req.Header.Set("Authorization", "Bearer "+tokenString)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
