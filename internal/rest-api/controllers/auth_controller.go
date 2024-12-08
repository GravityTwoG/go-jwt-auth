package controllers

import (
	"crypto/rsa"
	"errors"
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

	auth.GET("/oauth-providers", ac.getSupportedOAuthProviders)

	auth.GET("/:provider/consent", ac.requestConsentURL)
	auth.POST("/:provider/register-callback", anonMiddleware, ac.registerWithOAuth)
	auth.POST("/:provider/login-callback", anonMiddleware, ac.loginWithOAuth)
	// user must be logged in to connect oauth provider
	auth.POST("/:provider/connect-callback", authMiddleware, ac.connectOAuth)

	auth.POST("/logout", authMiddleware, ac.logout)
	auth.POST("/logout-all", authMiddleware, ac.logoutAll)
	auth.POST("/delete-user", authMiddleware, ac.deleteUser)

	auth.POST("/refresh-tokens", ac.refreshTokens)

	auth.GET("/me", authMiddleware, ac.me)
	auth.GET("/me/active-sessions", authMiddleware, ac.activeSessions)
	auth.GET("/me/auth-providers", authMiddleware, ac.getAuthProviders)

	auth.GET("/config", ac.config)
}

// @Tags		Auth
// @Summary	Registers new user, also sets refresh token in cookie
// @Accept		json
// @Produce	json
// @Param		body	body		dto.RegisterDTO	true	"RegisterDTO"
// @Success	201		{object}	dto.RegisterResponseDTO
// @Failure	400		{object}	dto.ErrorResponseDTO
// @Router		/auth/register [post]
func (ac *authController) register(c *gin.Context) {
	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	registerDTO, err := ginutils.DecodeJSON[*dto.RegisterDTO](c)
	if err != nil {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	user, tokens, derr := ac.authService.Register(
		c,
		registerDTO,
		ip,
		userAgent,
		services.LocalAuthProvider,
	)
	if derr != nil {
		ginutils.WriteError(c, derr)
		return
	}

	ac.setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusCreated, &dto.RegisterResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken.GetToken(),
		User:         *dto.UserFromEntity(user),
	})
}

// @Tags		Auth
// @Summary	Login user
// @Description Logins user, also sets refresh token in cookie
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
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
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
		ginutils.WriteError(c, derr)
		return
	}

	ac.setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusOK, &dto.LoginResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken.GetToken(),
		User:         *dto.UserFromEntity(user),
	})
}

// @Tags		Auth
// @Summary	Get supported oauth providers
// @Description Get supported oauth providers
// @Produce	json
// @Success	200	{object}	[]string
// @Router		/auth/oauth-providers [get]
func (ac *authController) getSupportedOAuthProviders(c *gin.Context) {
	c.JSON(http.StatusOK, ac.authService.GetSupportedAuthProviders())
}

// @Tags		Auth
// @Summary	Request redirect URL for oauth provider consent screen
// @Description Logins user, also sets refresh token in cookie
// @Produce	json
// @Param redirectURL query string true "redirectURL"
// @Success	200		{object}	dto.OAuthRedirectDTO
// @Router		/auth/{provider}/consent [get]
func (ac *authController) requestConsentURL(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is required",
		))
		return
	}

	redirectURL := c.Query("redirectURL")
	if redirectURL == "" {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_QUERY_PARAMS",
			"redirectURL is required",
		))
		return
	}

	oauthConsentDTO, err := ac.authService.RequestConsentURL(
		c,
		provider,
		redirectURL,
	)
	if err != nil {
		ginutils.WriteError(c, err)
		return
	}

	c.JSON(http.StatusOK, &dto.OAuthRedirectDTO{
		RedirectURL:  oauthConsentDTO.RedirectURL,
		CodeVerifier: oauthConsentDTO.CodeVerifier,
	})
}

// @Tags		Auth
// @Summary	Registers new user with oauth provider, also sets refresh token in cookie
// @Accept		json
// @Produce	json
// @Param		body	body		dto.RegisterWithOAuthDTO	true	"RegisterWithOAuthDTO"
// @Success	201		{object}	dto.RegisterResponseDTO
// @Failure	400		{object}	dto.ErrorResponseDTO
// @Router		/auth/{provider}/register-callback [post]
func (ac *authController) registerWithOAuth(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is required",
		))
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	registerWithOAuthDTO, err := ginutils.DecodeJSON[*dto.RegisterWithOAuthDTO](c)
	if err != nil {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	user, tokens, derr := ac.authService.RegisterWithOAuth(
		c,
		provider,
		registerWithOAuthDTO,
		ip,
		userAgent,
	)
	if derr != nil {
		ginutils.WriteError(c, derr)
		return
	}

	ac.setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusCreated, &dto.RegisterResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken.GetToken(),
		User:         *dto.UserFromEntity(user),
	})
}

// @Tags		Auth
// @Summary	Login user with oauth provider
// @Description Logins user, also sets refresh token in cookie
// @Accept		json
// @Produce	json
// @Param		body	body		dto.LoginWithOAuthDTO	true	"LoginWithOAuthDTO"
// @Success	200		{object}	dto.LoginResponseDTO
// @Failure	400		{object}	dto.ErrorResponseDTO
// @Failure	401		{object}	dto.ErrorResponseDTO
// @Router		/auth/{provider}/login-callback [post]
func (ac *authController) loginWithOAuth(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is required",
		))
		return
	}

	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	loginWithOAuthDTO, err := ginutils.DecodeJSON[*dto.LoginWithOAuthDTO](c)
	if err != nil {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	user, tokens, derr := ac.authService.LoginWithOAuth(
		c,
		provider,
		ip,
		userAgent,
		loginWithOAuthDTO,
	)
	if derr != nil {
		ginutils.WriteError(c, derr)
		return
	}

	ac.setRefreshTokenCookie(c, &tokens.RefreshToken)

	c.JSON(http.StatusOK, &dto.LoginResponseDTO{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken.GetToken(),
		User:         *dto.UserFromEntity(user),
	})
}

// @Tags		Auth
// @Summary	Connect oauth provider
// @Description Connects oauth provider
// @Accept		json
// @Produce	json
// @Param		body	body		dto.ConnectOAuthDTO	true	"ConnectOAuthDTO"
// @Success	200		{object}	dto.ConnectOAuthResponseDTO
// @Failure	400		{object}	dto.ErrorResponseDTO
// @Failure	401		{object}	dto.ErrorResponseDTO
// @Router		/auth/{provider}/connect-callback [post]
func (ac *authController) connectOAuth(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is required",
		))
		return
	}

	user := middlewares.ExtractUser(c)
	if user == nil {
		ginutils.WriteError(c, domainerrors.NewErrUnknown(
			errors.New("internal server error"),
		))
		return
	}

	connectOAuthDTO, err := ginutils.DecodeJSON[*dto.ConnectOAuthDTO](c)
	if err != nil {
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	derr := ac.authService.ConnectOAuth(
		c,
		provider,
		connectOAuthDTO,
		user.ID,
	)
	if derr != nil {
		ginutils.WriteError(c, derr)
		return
	}

	c.JSON(http.StatusOK, &dto.ConnectOAuthResponseDTO{
		Message: "Connected",
	})
}

// @Tags		Auth
// @Summary	Refresh tokens
// @Description Refreshes tokens, also sets new refresh token in cookie
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
		ginutils.WriteError(c, domainerrors.NewErrInvalidInput(
			"INVALID_BODY",
			err.Error(),
		))
		return
	}

	refreshToken, cookieErr := c.Cookie(cookieName)
	if cookieErr != nil {
		ginutils.WriteErrorWithStatus(
			c,
			http.StatusUnauthorized,
			ErrRefreshTokenNotFound,
		)
		return
	}

	tokens, err := ac.authService.RefreshTokens(c, &services.RefreshTokensDTO{
		OldToken:    refreshToken,
		IP:          c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
		FingerPrint: refreshTokensDTO.FingerPrint,
	})
	if err != nil {
		switch err.Code() {
		case services.InvalidRefreshToken,
			services.RefreshTokenExpired,
			domainerrors.EntityNotFound,
			services.InvalidUserAgent,
			services.InvalidFingerPrint:

			ac.resetRefreshTokenCookie(c)
		}

		ginutils.WriteError(c, err)
		return
	}

	ac.setRefreshTokenCookie(c, &tokens.RefreshToken)

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
		ginutils.WriteError(c, err)
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
// @Router		/auth/me/active-sessions [get]
func (ac *authController) activeSessions(c *gin.Context) {
	userDTO := middlewares.ExtractUser(c)

	sessions, err := ac.authService.GetActiveSessions(
		c,
		userDTO.ID,
	)
	if err != nil {
		ginutils.WriteError(c, err)
		return
	}

	sessionsDTO := dto.SessionsDTOFromEntities(sessions)

	c.JSON(http.StatusOK, sessionsDTO)
}

// @Tags		Auth
// @Summary	Get user auth providers
// @Description	Get user auth providers
// @Produce	json
// @Success	200	{object}	[]dto.UserAuthProviderDTO
// @Router		/auth/me/auth-providers [get]
func (ac *authController) getAuthProviders(c *gin.Context) {
	userID := middlewares.ExtractUser(c).ID

	providers, err := ac.authService.GetAuthProviders(
		c,
		userID,
	)
	if err != nil {
		ginutils.WriteError(c, err)
		return
	}

	providersDTO := make([]dto.UserAuthProviderDTO, 0, len(providers))
	for i := 0; i < len(providers); i++ {
		providersDTO = append(providersDTO, dto.UserAuthProviderDTO{
			Name:  providers[i].GetName(),
			Email: providers[i].GetEmail(),
		})
	}

	c.JSON(http.StatusOK, providersDTO)
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
		ac.resetRefreshTokenCookie(c)

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
		ac.resetRefreshTokenCookie(c)

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
		ginutils.WriteErrorWithStatus(
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
			&dto.CommonResponseDTO{
				Message: "Internal server error",
			},
		)
		return
	}

	// Delete refresh token from cookie
	ac.resetRefreshTokenCookie(c)

	c.JSON(http.StatusOK, &dto.CommonResponseDTO{
		Message: "Logged out",
	})
}

// @Tags		Auth
// @Summary	Delete user
// @Security	ApiKeyAuth
// @Produce	json
// @Success	200	{object}	dto.CommonResponseDTO
// @Router		/auth/delete-user [post]
func (ac *authController) deleteUser(c *gin.Context) {
	user := middlewares.ExtractUser(c)
	if user == nil {
		ginutils.WriteError(c, domainerrors.NewErrUnknown(
			errors.New("user not found"),
		))
		return
	}

	err := ac.authService.DeleteUser(c, user.ID)
	if err != nil {
		ginutils.WriteError(c, err)
		return
	}

	ac.resetRefreshTokenCookie(c)

	c.JSON(http.StatusOK, &dto.CommonResponseDTO{
		Message: "User deleted",
	})
}

func (ac *authController) setRefreshTokenCookie(
	c *gin.Context,
	refreshToken *entities.RefreshToken,
) {
	c.SetSameSite(http.SameSiteNoneMode)
	c.SetCookie(
		cookieName, refreshToken.GetToken(),
		refreshToken.GetTTLSec(), ac.path, ac.domain, true, true,
	)
}

func (ac *authController) resetRefreshTokenCookie(
	c *gin.Context,
) {
	c.SetSameSite(http.SameSiteNoneMode)
	c.SetCookie(cookieName, "", -1, ac.path, ac.domain, true, true)
}
