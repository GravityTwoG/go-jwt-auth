package controllers

import (
	"net/http"

	domain_errors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/middlewares"
	"go-jwt-auth/internal/rest-api/services"
	gin_utils "go-jwt-auth/pkg/gin-utils"

	"github.com/gin-gonic/gin"
)

const cookieName = "refreshToken"

var ErrRefreshTokenNotFound = domain_errors.NewErrEntityNotFound(
	"refresh token not found in cookie",
)

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
	anonMiddleware := middlewares.AnonymousMiddleware(ac.jwtSecretKey)
	authMiddleware := middlewares.AuthMiddleware(ac.jwtSecretKey)

	r.POST("/register", anonMiddleware, ac.register)
	r.POST("/login", anonMiddleware, ac.login)
	r.POST("/logout", ac.logout)

	r.POST("/refresh-tokens", ac.refreshTokens)

	r.GET("/me", authMiddleware, ac.me)
	r.GET("/active-sessions", authMiddleware, ac.activeSessions)
}

// @Tags		Auth
// @Summary	Register new user
// @Accept		json
// @Produce	json
// @Param		body	body		dto.RegisterDTO	true	"RegisterDTO"
// @Success	201		{object}	dto.UserDTO
// @Router		/register [post]
func (ac *AuthController) register(c *gin.Context) {

	registerDTO, err := gin_utils.DecodeJSON[*dto.RegisterDTO](c)
	if err != nil {
		writeError(c, domain_errors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	user, derr := ac.authService.Register(c, registerDTO)
	if derr != nil {
		writeError(c, derr)
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

	loginDTO, err := gin_utils.DecodeJSON[*dto.LoginDTO](c)
	if err != nil {
		writeError(c, domain_errors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	user, tokens, derr := ac.authService.Login(c, loginDTO)
	if derr != nil {
		writeError(c, derr)
		return
	}

	setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"accessToken": tokens.AccessToken,
		"user":        dto.FromEntity(user),
	})
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
		writeErrorWithStatus(
			c,
			http.StatusUnauthorized,
			ErrRefreshTokenNotFound,
		)
		return
	}

	tokens, derr := ac.authService.RefreshTokens(c, refreshToken)
	if derr != nil {
		writeError(c, derr)
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
	userDTO := middlewares.ExtractUser(c)

	user, err := ac.authService.GetUserByID(c, userDTO.ID)
	if err != nil {
		writeError(c, err)
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
	userDTO := middlewares.ExtractUser(c)

	sessions, err := ac.authService.ActiveSessions(c, userDTO.Email)
	if err != nil {
		writeError(c, err)
		return
	}

	sessionsDTO := []string{}
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
		// Should logout in any case

		// Delete refresh token from cookie
		resetCookie(c, cookieName)

		c.JSON(http.StatusOK, gin.H{"message": err.Error()})
	} else {
		ac.authService.Logout(c, refreshToken)

		// Delete refresh token from cookie
		resetCookie(c, cookieName)

		c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
	}
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

func resetCookie(c *gin.Context, name string) {
	c.SetCookie(name, "", -1, "/", "", false, true)
}

func writeError(
	c *gin.Context,
	err domain_errors.ErrDomain,
) {
	status := http.StatusInternalServerError

	switch {
	case err.Kind() == domain_errors.EntityNotFound:
		status = http.StatusNotFound
	case err.Kind() == domain_errors.InvalidInput:
		status = http.StatusConflict
	case err.Kind() == domain_errors.InvalidInput:
		status = http.StatusBadRequest
	}

	writeErrorWithStatus(c, status, err)
}

func writeErrorWithStatus(
	c *gin.Context,
	status int,
	err domain_errors.ErrDomain,
) {
	c.JSON(status, gin.H{
		"kind":  err.Kind(),
		"code":  err.Code(),
		"error": err.Error(),
	})
}
