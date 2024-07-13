package controllers

import (
	"crypto/rsa"
	"fmt"
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

type authController struct {
	authService services.AuthService

	jwtPublicKey *rsa.PublicKey
	domain       string
	path         string
}

func NewAuthController(
	r *gin.RouterGroup,
	authService services.AuthService,
	jwtPublicKey *rsa.PublicKey,
	domain string,
	path string,
) {
	ac := authController{
		authService: authService,

		jwtPublicKey: jwtPublicKey,
		domain:       domain,
		path:         path,
	}

	anonMiddleware := middlewares.AnonymousMiddleware(ac.jwtPublicKey)
	authMiddleware := middlewares.AuthMiddleware(ac.jwtPublicKey)

	auth := r.Group("/auth")

	auth.POST("/register", anonMiddleware, ac.register)
	auth.POST("/login", anonMiddleware, ac.login)
	auth.POST("/logout", authMiddleware, ac.logout)
	auth.POST("/logout-all", authMiddleware, ac.logoutAll)

	auth.POST("/refresh-tokens", ac.refreshTokens)

	auth.GET("/me", authMiddleware, ac.me)
	auth.GET("/active-sessions", authMiddleware, ac.activeSessions)
	auth.GET("/config", ac.config)
}

// @Tags		Auth
// @Summary	Register new user
// @Accept		json
// @Produce	json
// @Param		body	body		dto.RegisterDTO	true	"RegisterDTO"
// @Success	201		{object}	dto.UserDTO
// @Failure	400		{object}	dto.ErrorResponseDTO
// @Router		/auth/register [post]
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

	c.JSON(http.StatusCreated, dto.UserFromEntity(user))
}

// @Tags		Auth
// @Summary	Login user
// @Description Login user, also sets refresh token in cookie
// @Accept		json
// @Produce	json
// @Param		body	body		dto.LoginDTO	true	"LoginDTO"
// @Success	200		{object}	dto.LoginResponseDTO
// @Failure	400		{object}	dto.ErrorResponseDTO
// @Failure	401		{object}	dto.ErrorResponseDTO
// @Router		/auth/login [post]
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

	setRefreshTokenCookie(c, &tokens.RefreshToken, ac.domain, ac.path)

	c.JSON(http.StatusOK, &dto.LoginResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken.GetToken(),
		User:         *dto.UserFromEntity(user),
	})
}

// @Tags		Auth
// @Summary	Refresh tokens
// @Description Refresh tokens, also sets new refresh token in cookie
// @Security	ApiKeyAuth
// @Accept		json
// @Produce	json
// @Param		body	body		dto.RefreshTokensDTO	true	"RefreshTokensDTO"
// @Success	200	{object}	dto.RefreshTokensResponseDTO
// @Failure	401	{object}	dto.ErrorResponseDTO
// @Router		/auth/refresh-tokens [post]
func (ac *authController) refreshTokens(c *gin.Context) {
	refreshTokensDTO, err := ginutils.DecodeJSON[*dto.RefreshTokensDTO](c)
	if err != nil {
		writeError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	refreshToken, err := c.Cookie(cookieName)
	if err != nil {
		writeErrorWithStatus(
			c,
			http.StatusUnauthorized,
			ErrRefreshTokenNotFound,
		)
		return
	}

	tokens, derr := ac.authService.RefreshTokens(c, &services.RefreshTokensDTO{
		OldToken:    refreshToken,
		IP:          c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
		FingerPrint: refreshTokensDTO.FingerPrint,
	})
	if derr != nil {

		switch derr.Code() {
		case services.InvalidRefreshToken,
			services.RefreshTokenExpired,
			domainerrors.EntityNotFound,
			services.InvalidUserAgent,
			services.InvalidFingerPrint:

			resetCookie(c, cookieName, ac.domain, ac.path)
		}

		writeError(c, derr)
		return
	}

	setRefreshTokenCookie(c, &tokens.RefreshToken, ac.domain, ac.path)

	c.JSON(http.StatusOK, &dto.RefreshTokensResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken.GetToken(),
	})
}

// @Tags		Auth
// @Summary	Get current user
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	dto.UserDTO
// @Router		/auth/me [get]
func (ac *authController) me(c *gin.Context) {
	userDTO := middlewares.ExtractUser(c)

	user, err := ac.authService.GetUserByID(c, userDTO.ID)
	if err != nil {
		writeError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.UserFromEntity(user))
}

// @Tags		Auth
// @Summary	Get active sessions
// @Description	Get active sessions (list of refresh tokens)
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	dto.SessionsDTO
// @Router		/auth/active-sessions [get]
func (ac *authController) activeSessions(c *gin.Context) {
	userDTO := middlewares.ExtractUser(c)

	sessions, err := ac.authService.GetActiveSessions(
		c,
		userDTO.ID,
	)
	if err != nil {
		writeError(c, err)
		return
	}

	sessionsDTO := dto.SessionsDTOFromEntities(sessions)

	c.JSON(http.StatusOK, sessionsDTO)
}

// @Tags		Auth
// @Summary	Get tokens config
// @Description	Get TTL of tokens
// @Produce	json
// @Success	200	{object}	dto.ConfigDTO
// @Router		/auth/config [get]
func (ac *authController) config(c *gin.Context) {
	config := ac.authService.GetConfig(c)
	c.JSON(http.StatusOK, config)
}

// @Tags		Auth
// @Summary	Logout user
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	dto.CommonResponseDTO
// @Router		/auth/logout [post]
func (ac *authController) logout(c *gin.Context) {
	refreshToken, err := c.Cookie(cookieName)
	if err != nil {
		// Should logout in any case

		// Delete refresh token from cookie
		resetCookie(c, cookieName, ac.domain, ac.path)

		c.JSON(http.StatusOK, &dto.CommonResponseDTO{
			Message: err.Error(),
		})
	} else {
		err = ac.authService.Logout(
			c,
			refreshToken,
			c.GetHeader("User-Agent"),
		)
		if err != nil {
			fmt.Println("Logout error: ", err)
		}

		// Delete refresh token from cookie
		resetCookie(c, cookieName, ac.domain, ac.path)

		c.JSON(http.StatusOK, &dto.CommonResponseDTO{
			Message: "Logged out",
		})
	}
}

// @Tags		Auth
// @Summary	Logout all sessions
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	dto.CommonResponseDTO
// @Router		/auth/logout-all [post]
func (ac *authController) logoutAll(c *gin.Context) {
	refreshToken, err := c.Cookie(cookieName)
	if err != nil {
		writeErrorWithStatus(
			c,
			http.StatusUnauthorized,
			ErrRefreshTokenNotFound,
		)
		return
	}

	err = ac.authService.LogoutAll(
		c,
		refreshToken,
		c.GetHeader("User-Agent"),
	)
	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"message": "Internal server error"},
		)
		return
	}

	// Delete refresh token from cookie
	resetCookie(c, cookieName, ac.domain, ac.path)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func setRefreshTokenCookie(
	c *gin.Context,
	refreshToken *entities.RefreshToken,
	domain string,
	path string,
) {
	c.SetCookie(
		cookieName, refreshToken.GetToken(),
		refreshToken.GetTTLSec(), path, domain, true, true,
	)
}

func resetCookie(
	c *gin.Context,
	name string,
	domain string,
	path string,
) {
	c.SetCookie(name, "", -1, path, domain, true, true)
}

func writeError(
	c *gin.Context,
	err domainerrors.ErrDomain,
) {
	status := http.StatusInternalServerError

	switch {
	case err.Kind() == domainerrors.EntityNotFound:
		status = http.StatusNotFound
	case err.Kind() == domainerrors.EntityAlreadyExists:
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
