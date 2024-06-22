package controllers

import (
	"net/http"
	"strings"
	"time"

	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/services"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const cookieName = "refreshToken"

type AuthController struct {
	authService services.AuthService

	jwtSecretKey []byte
}

func NewAuthController(
	authService services.AuthService,
	jwtSecretKey string,
) *AuthController {
	return &AuthController{
		authService: authService,

		jwtSecretKey: []byte(jwtSecretKey),
	}
}

func (ac *AuthController) RegisterRoutes(r *gin.Engine) {
	r.POST("/register", AnonymousMiddleware(ac.jwtSecretKey), ac.register)
	r.POST("/login", AnonymousMiddleware(ac.jwtSecretKey), ac.login)
	r.POST("/logout", ac.logout)

	r.POST("/refresh-tokens", ac.refreshTokens)

	r.GET("/me", AuthMiddleware(ac.jwtSecretKey), ac.me)
	r.GET("/active-sessions", AuthMiddleware(ac.jwtSecretKey), ac.activeSessions)
}

// @Tags		Auth
// @Summary	Register new user
// @Accept		json
// @Produce	json
// @Param		body	body		dto.RegisterDTO	true	"RegisterDTO"
// @Success	201		{object}	dto.UserDTO
// @Router		/register [post]
func (ac *AuthController) register(c *gin.Context) {
	var registerDTO dto.RegisterDTO
	if err := c.ShouldBindJSON(&registerDTO); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := ac.authService.Register(c, &registerDTO)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, dto.FromEntity(user))
}

type LoginResponeDTO struct {
	AccessToken string `json:"accessToken"`
	User        dto.UserDTO
}

// @Tags		Auth
// @Summary	Login user
// @Description Login user, also sets refresh token in cookie
// @Accept		json
// @Produce	json
// @Param		body	body		dto.LoginDTO	true	"LoginDTO"
// @Success	200		{object}	LoginResponeDTO
// @Router		/login [post]
func (ac *AuthController) login(c *gin.Context) {

	var loginDTO dto.LoginDTO
	if err := c.ShouldBindJSON(&loginDTO); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, tokens, err := ac.authService.Login(c, &loginDTO)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"accessToken": tokens.AccessToken,
		"user":        dto.FromEntity(user),
	})
}

func setRefreshTokenCookie(
	c *gin.Context,
	refreshToken *entities.RefreshToken,
) {
	c.SetCookie(
		cookieName, refreshToken.GetToken(),
		refreshToken.GetTtlSec(), "/", "", false, true,
	)
}

type RefreshTokensResponeDTO struct {
	AccessToken string `json:"accessToken"`
}

// @Tags		Auth
// @Summary	Refresh tokens
// @Description Refresh tokens, also sets new refresh token in cookie
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	RefreshTokensResponeDTO
// @Router		/refresh-tokens [post]
func (ac *AuthController) refreshTokens(c *gin.Context) {

	refreshToken, err := c.Cookie(cookieName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := ac.authService.RefreshTokens(c, refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusOK, gin.H{"accessToken": tokens.AccessToken})
}

// @Tags		Auth
// @Summary	Get current user
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	dto.UserDTO
// @Router		/me [get]
func (ac *AuthController) me(c *gin.Context) {
	email, _ := c.Get("email")

	user, err := ac.authService.GetUser(c, email.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dto.FromEntity(user))
}

// @Tags		Auth
// @Summary	Get active sessions
// @Description	Get active sessions (list of refresh tokens)
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{array}	string
// @Router		/active-sessions [get]
func (ac *AuthController) activeSessions(c *gin.Context) {
	email, _ := c.Get("email")

	sessions, err := ac.authService.ActiveSessions(c, email.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var sessionsDTO []string
	for _, session := range sessions {
		sessionsDTO = append(sessionsDTO, session.GetToken())
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessionsDTO})
}

type LogoutResponeDTO struct {
	Message string `json:"message"`
}

// @Tags		Auth
// @Summary	Logout user
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	LogoutResponeDTO
// @Router		/logout [post]
func (ac *AuthController) logout(c *gin.Context) {
	refreshToken, err := c.Cookie(cookieName)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": err.Error()})
		return
	}

	ac.authService.Logout(c, refreshToken)

	// Delete refresh token from cookie
	c.SetCookie(cookieName, "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func AuthMiddleware(jwtSecretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		// Check if the Authorization header has the correct format
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		// Extract the token
		tokenString := parts[1]

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecretKey, nil
		})

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
			// Set the claims to the context
			c.Set("email", claims["email"])
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}
	}
}

func AnonymousMiddleware(jwtSecretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Check if the Authorization header has the correct format
		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
			c.Abort()
			return
		}

		// Extract the token
		tokenString := parts[1]

		// Parse and validate the token
		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the alg is what we expect
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecretKey, nil
		})

		if err != nil {
			c.Next()
			return
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Already logged in"})
		c.Abort()
	}
}
