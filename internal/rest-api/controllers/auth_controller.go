package controllers

import (
	"net/http"

	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/middlewares"
	"go-jwt-auth/internal/rest-api/services"
	ginutils "go-jwt-auth/pkg/gin-utils"

	"github.com/gin-gonic/gin"
)

const cookieName = "refreshToken"

var ErrRefreshTokenNotFound = domainerrors.NewErrEntityNotFound(
	"REFRESH_TOKEN_NOT_FOUND",
	"refresh token not found in cookie",
)

type CommonResponseDTO struct {
	Message string `json:"message"`
}

type ErrorResponseDTO struct {
	Kind  string `json:"kind"`
	Code  string `json:"code"`
	Error string `json:"error"`
}

type authController struct {
	authService services.AuthService

	jwtSecretKey []byte
}

func NewAuthController(
	authService services.AuthService,
	jwtSecretKey string,
) *authController {
	return &authController{
		authService: authService,

		jwtSecretKey: []byte(jwtSecretKey),
	}
}

func (ac *authController) RegisterRoutes(r *gin.Engine) {
	anonMiddleware := middlewares.AnonymousMiddleware(ac.jwtSecretKey)
	authMiddleware := middlewares.AuthMiddleware(ac.jwtSecretKey)

	r.POST("/register", anonMiddleware, ac.register)
	r.POST("/login", anonMiddleware, ac.login)
	r.POST("/logout", authMiddleware, ac.logout)
	r.POST("/logout-all", authMiddleware, ac.logoutAll)

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
// @Failure	400		{object}	ErrorResponseDTO
// @Router		/register [post]
func (ac *authController) register(c *gin.Context) {

	registerDTO, err := ginutils.DecodeJSON[*dto.RegisterDTO](c)
	if err != nil {
		writeError(c, domainerrors.NewErrInvalidInput(
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
// @Failure	400		{object}	ErrorResponseDTO
// @Failure	401		{object}	ErrorResponseDTO
// @Router		/login [post]
func (ac *authController) login(c *gin.Context) {

	loginDTO, err := ginutils.DecodeJSON[*dto.LoginDTO](c)
	if err != nil {
		writeError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	user, tokens, derr := ac.authService.Login(
		c,
		loginDTO,
		ip,
		userAgent,
	)
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
// @Failure	401	{object}	ErrorResponseDTO
// @Router		/refresh-tokens [post]
func (ac *authController) refreshTokens(c *gin.Context) {

	refreshToken, err := c.Cookie(cookieName)
	if err != nil {
		writeErrorWithStatus(
			c,
			http.StatusUnauthorized,
			ErrRefreshTokenNotFound,
		)
		return
	}

	dto := &services.RefreshTokensDTO{
		OldToken:  refreshToken,
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
	}
	tokens, derr := ac.authService.RefreshTokens(c, dto)
	if derr != nil {
		isExpired := derr.Code() == services.RefreshTokenExpired
		notFound := derr.Code() == domainerrors.EntityNotFound
		if isExpired || notFound {
			resetCookie(c, cookieName)
		}

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
func (ac *authController) me(c *gin.Context) {
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
// @Success	200	{object}	dto.SessionsDTO
// @Router		/active-sessions [get]
func (ac *authController) activeSessions(c *gin.Context) {
	userDTO := middlewares.ExtractUser(c)

	sessions, err := ac.authService.ActiveSessions(c, userDTO.Email)
	if err != nil {
		writeError(c, err)
		return
	}

	sessionsDTO := dto.SessionsDTOFromEntities(sessions)

	c.JSON(http.StatusOK, sessionsDTO)
}

// @Tags		Auth
// @Summary	Logout user
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	CommonResponseDTO
// @Router		/logout [post]
func (ac *authController) logout(c *gin.Context) {
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

// @Tags		Auth
// @Summary	Logout all sessions
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	CommonResponseDTO
// @Router		/logout-all [post]
func (ac *authController) logoutAll(c *gin.Context) {
	userDTO := middlewares.ExtractUser(c)
	err := ac.authService.LogoutAll(c, userDTO.ID)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"message": "Internal server error"},
		)
		return
	}

	// Delete refresh token from cookie
	resetCookie(c, cookieName)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
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
	err domainerrors.ErrDomain,
) {
	status := http.StatusInternalServerError

	switch {
	case err.Kind() == domainerrors.EntityNotFound:
		status = http.StatusNotFound
	case err.Kind() == domainerrors.InvalidInput:
		status = http.StatusConflict
	case err.Kind() == domainerrors.InvalidInput:
		status = http.StatusBadRequest
	}

	writeErrorWithStatus(c, status, err)
}

func writeErrorWithStatus(
	c *gin.Context,
	status int,
	err domainerrors.ErrDomain,
) {
	c.JSON(status, gin.H{
		"kind":  err.Kind(),
		"code":  err.Code(),
		"error": err.Error(),
	})
}
