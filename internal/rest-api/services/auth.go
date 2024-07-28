package services

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/services/oauth"
	"log"
	"time"

	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
	"github.com/google/uuid"
)

const InvalidRefreshToken = "INVALID_REFRESH_TOKEN"
const RefreshTokenExpired = "REFRESH_TOKEN_EXPIRED"
const RefreshTokenNotFound = "REFRESH_TOKEN_NOT_FOUND"
const InvalidUserAgent = "INVALID_USER_AGENT"
const InvalidFingerPrint = "INVALID_FINGER_PRINT"

var (
	ErrEmailAlreadyExists = domainerrors.NewErrEntityAlreadyExists(
		"EMAIL_ALREADY_EXISTS",
		"email already exists",
	)

	ErrPasswordsDontMatch = domainerrors.NewErrInvalidInput(
		"PASSWORDS_DONT_MATCH",
		"passwords don't match",
	)

	ErrIncorrectEmailOrPassword = domainerrors.NewErrInvalidInput(
		"INCORRECT_EMAIL_OR_PASSWORD",
		"incorrect email or password",
	)
)

type Tokens struct {
	AccessToken  string
	RefreshToken entities.RefreshToken
}

type RefreshTokensDTO struct {
	OldToken    string
	IP          string
	UserAgent   string
	FingerPrint string
}

type UserRepository interface {
	Create(
		ctx context.Context,
		user *entities.User,
	) domainerrors.ErrDomain

	GetByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domainerrors.ErrDomain)

	GetByEmail(
		ctx context.Context,
		email string,
	) (*entities.User, domainerrors.ErrDomain)
}

type RefreshTokenRepository interface {
	Create(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
	) domainerrors.ErrDomain

	Update(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
	) domainerrors.ErrDomain

	GetByToken(
		ctx context.Context,
		token string,
	) (*entities.RefreshToken, domainerrors.ErrDomain)

	GetByUserID(
		ctx context.Context,
		id uint,
	) ([]*entities.RefreshToken, domainerrors.ErrDomain)

	Delete(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
	) domainerrors.ErrDomain

	DeleteByUserID(
		ctx context.Context,
		userID uint,
	) domainerrors.ErrDomain

	DeleteExpired(
		ctx context.Context) domainerrors.ErrDomain
}

type JWTService interface {
	NewJWT(
		user *entities.User,
		ttlSec int,
	) (string, domainerrors.ErrDomain)

	VerifyAndParseJWT(
		tokenString string,
	) (*TokenClaims, error)
}

type AuthService interface {
	Register(
		ctx context.Context,
		dto *dto.RegisterDTO,
		ip string,
		userAgent string,
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	Login(
		ctx context.Context,
		dto *dto.LoginDTO,
		ip string,
		userAgent string,
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	RequestConsentURL(
		ctx context.Context,
		provider string,
		redirectURL string,
	) (string, domainerrors.ErrDomain)

	RegisterWithOAuth(
		ctx context.Context,
		provider string,
		dto *dto.RegisterWithOAuthDTO,
		ip string,
		userAgent string,
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	LoginWithOAuth(
		ctx context.Context,
		provider string,
		ip string,
		userAgent string,
		dto *dto.LoginWithOAuthDTO,
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	RefreshTokens(
		ctx context.Context,
		dto *RefreshTokensDTO,
	) (*Tokens, domainerrors.ErrDomain)

	GetUserByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domainerrors.ErrDomain)

	GetActiveSessions(
		ctx context.Context,
		id uint,
	) ([]*entities.RefreshToken, domainerrors.ErrDomain)

	GetConfig(ctx context.Context) *dto.ConfigDTO

	Logout(
		ctx context.Context,
		refreshToken string,
		userAgent string,
	) domainerrors.ErrDomain

	LogoutAll(
		ctx context.Context,
		refreshToken string,
		userAgent string,
	) domainerrors.ErrDomain

	RunScheduledTasks(ctx context.Context)
}

type authService struct {
	trManager *manager.Manager

	userRepo UserRepository

	refreshTokenRepository RefreshTokenRepository

	jwtService JWTService

	accessTokenTTLsec  int
	refreshTokenTTLsec int

	oauthServices map[string]oauth.OAuthService
}

func NewAuthService(
	trManager *manager.Manager,
	userRepo UserRepository,
	refreshTokenRepository RefreshTokenRepository,
	jwtService JWTService,
	accessTokenTTLsec int,
	refreshTokenTTLsec int,
	oauthServices map[string]oauth.OAuthService,
) AuthService {

	return &authService{
		trManager: trManager,

		userRepo: userRepo,

		refreshTokenRepository: refreshTokenRepository,

		jwtService: jwtService,

		accessTokenTTLsec:  accessTokenTTLsec,
		refreshTokenTTLsec: refreshTokenTTLsec,

		oauthServices: oauthServices,
	}
}

func (s *authService) Register(
	ctx context.Context,
	registerDTO *dto.RegisterDTO,
	ip string,
	userAgent string,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {

	if registerDTO.Password != registerDTO.Password2 {
		return nil, nil, ErrPasswordsDontMatch
	}

	user, err := entities.NewUser(
		registerDTO.Email,
		registerDTO.Password,
	)
	if err != nil {
		return nil, nil, err
	}

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		if err.Kind() == domainerrors.EntityAlreadyExists {
			return nil, nil, ErrEmailAlreadyExists
		}

		return nil, nil, err
	}

	tokens, err := s.createTokensPair(
		ctx,
		user,
		ip,
		userAgent,
		registerDTO.FingerPrint,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *authService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
	ip string,
	userAgent string,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {

	user, err := s.userRepo.GetByEmail(ctx, loginDTO.Email)
	if err != nil {
		if err.Kind() == domainerrors.EntityNotFound {
			return nil, nil, ErrIncorrectEmailOrPassword
		}

		return nil, nil, err
	}

	if !user.ComparePassword(loginDTO.Password) {
		return nil, nil, ErrIncorrectEmailOrPassword
	}

	tokens, err := s.createTokensPair(
		ctx,
		user,
		ip,
		userAgent,
		loginDTO.FingerPrint,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *authService) createTokensPair(
	ctx context.Context,
	user *entities.User,
	ip string,
	userAgent string,
	fingerPrint string,
) (*Tokens, domainerrors.ErrDomain) {
	accessToken, err := s.jwtService.NewJWT(
		user,
		s.accessTokenTTLsec,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtService.NewJWT(
		user,
		s.refreshTokenTTLsec,
	)
	if err != nil {
		return nil, err
	}

	refreshTokenEntity := entities.NewRefreshToken(
		refreshToken,
		user.GetID(),
		s.refreshTokenTTLsec,
		ip,
		userAgent,
		fingerPrint,
	)

	err = s.refreshTokenRepository.Create(ctx, refreshTokenEntity)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *refreshTokenEntity,
	}, nil
}

func (s *authService) RequestConsentURL(
	ctx context.Context,
	provider string,
	redirectURL string,
) (string, domainerrors.ErrDomain) {
	oauthService, ok := s.oauthServices[provider]
	if !ok {
		return "", domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is not supported",
		)
	}

	return oauthService.RequestConsentURL(
		ctx,
		redirectURL,
	), nil
}

func (s *authService) RegisterWithOAuth(
	ctx context.Context,
	provider string,
	registerWithOAuthDTO *dto.RegisterWithOAuthDTO,
	ip string,
	userAgent string,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {
	oauthService, ok := s.oauthServices[provider]
	if !ok {
		return nil, nil, domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is not supported",
		)
	}
	email, err := oauthService.FetchUserEmail(
		ctx,
		registerWithOAuthDTO.Code,
		registerWithOAuthDTO.RedirectURL,
	)

	if err != nil {
		return nil, nil, err
	}

	password := uuid.New().String()

	registerDTO := &dto.RegisterDTO{
		Email:       email,
		Password:    password,
		Password2:   password,
		FingerPrint: registerWithOAuthDTO.FingerPrint,
	}

	return s.Register(ctx, registerDTO, ip, userAgent)
}

func (s *authService) LoginWithOAuth(
	ctx context.Context,
	provider string,
	ip string,
	userAgent string,
	dto *dto.LoginWithOAuthDTO,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {
	oauthService, ok := s.oauthServices[provider]
	if !ok {
		return nil, nil, domainerrors.NewErrInvalidInput(
			"INVALID_PROVIDER",
			"provider is not supported",
		)
	}
	email, err := oauthService.FetchUserEmail(
		ctx,
		dto.Code,
		dto.RedirectURL,
	)
	if err != nil {
		return nil, nil, err
	}

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}

	tokens, err := s.createTokensPair(
		ctx,
		user,
		ip,
		userAgent,
		dto.FingerPrint,
	)
	if err != nil {
		return nil, nil, err
	}

	return user, tokens, nil
}

func (s *authService) RefreshTokens(
	ctx context.Context,
	dto *RefreshTokensDTO,
) (*Tokens, domainerrors.ErrDomain) {

	tokenClaims, jwtErr := s.jwtService.VerifyAndParseJWT(dto.OldToken)
	if jwtErr != nil {
		return nil, domainerrors.NewErrInvalidInput(
			InvalidRefreshToken,
			"invalid or expired refresh token",
		)
	}

	var tokens *Tokens = nil
	var domainError domainerrors.ErrDomain = nil

	err := s.trManager.Do(ctx, func(ctx context.Context) error {

		tokens, domainError = s.refreshTokens(
			ctx,
			dto,
			tokenClaims.ID,
		)

		return domainError
	})

	if err != nil && domainError == nil {
		log.Printf("authService.RefreshTokens transaction err: %v", err)
	}

	return tokens, domainError
}

func (s *authService) refreshTokens(
	ctx context.Context,
	dto *RefreshTokensDTO,
	userID uint,
) (*Tokens, domainerrors.ErrDomain) {
	refreshTokenEntity, err := s.refreshTokenRepository.
		GetByToken(ctx, dto.OldToken)

	// Token with valid signature and expiration provided,
	// but this token doesn't exist in DB.
	// Maybe was stolen and deleted by another person.
	if err != nil && err.Kind() == domainerrors.EntityNotFound {
		_ = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			userID,
		)

		return nil, domainerrors.NewErrEntityNotFound(
			RefreshTokenNotFound,
			"refresh token not found. All refresh tokens were deleted",
		)
	}
	if err != nil {
		return nil, err
	}

	if refreshTokenEntity.GetUserAgent() != dto.UserAgent {
		_ = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			userID,
		)

		return nil, domainerrors.NewErrEntityNotFound(
			InvalidUserAgent,
			"invalid user agent. All refresh tokens were deleted",
		)
	}

	if refreshTokenEntity.GetFingerPrint() != dto.FingerPrint {
		_ = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			userID,
		)

		return nil, domainerrors.NewErrEntityNotFound(
			InvalidFingerPrint,
			"invalid finger print. All refresh tokens were deleted",
		)
	}

	// create new access token
	accessToken, err := s.jwtService.NewJWT(
		refreshTokenEntity.GetUser(),
		s.accessTokenTTLsec,
	)
	if err != nil {
		return nil, err
	}

	// create new refresh token
	newRefreshToken, err := s.jwtService.NewJWT(
		refreshTokenEntity.GetUser(),
		s.refreshTokenTTLsec,
	)
	if err != nil {
		return nil, err
	}

	refreshTokenEntity.SetToken(newRefreshToken)
	err = s.refreshTokenRepository.Update(ctx, refreshTokenEntity)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *refreshTokenEntity,
	}, nil
}

func (s *authService) GetUserByID(
	ctx context.Context,
	id uint,
) (*entities.User, domainerrors.ErrDomain) {

	return s.userRepo.GetByID(ctx, id)
}

func (s *authService) GetActiveSessions(
	ctx context.Context,
	id uint,
) ([]*entities.RefreshToken, domainerrors.ErrDomain) {

	return s.refreshTokenRepository.GetByUserID(ctx, id)
}

func (s *authService) GetConfig(
	ctx context.Context,
) *dto.ConfigDTO {
	return &dto.ConfigDTO{
		AccessTokenTTLsec:  s.accessTokenTTLsec,
		RefreshTokenTTLsec: s.refreshTokenTTLsec,
	}
}

func (s *authService) Logout(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {
	var domainError domainerrors.ErrDomain = nil

	err := s.trManager.Do(ctx, func(ctx context.Context) error {

		domainError = s.logout(ctx, refreshToken, userAgent)

		return domainError
	})

	if err != nil && domainError == nil {
		log.Printf("authService.Logout transaction err: %v", err)
	}

	return domainError
}

func (s *authService) logout(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {

	existingRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	if existingRefreshToken.GetUserAgent() != userAgent {
		return domainerrors.NewErrInvalidInput(
			InvalidUserAgent,
			"invalid user agent",
		)
	}

	return s.refreshTokenRepository.
		Delete(ctx, existingRefreshToken)
}

func (s *authService) LogoutAll(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {
	var domainError domainerrors.ErrDomain = nil

	err := s.trManager.Do(ctx, func(ctx context.Context) error {

		domainError = s.logoutAll(ctx, refreshToken, userAgent)

		return domainError
	})

	if err != nil && domainError == nil {
		log.Printf("authService.LogoutAll transaction err: %v", err)
	}

	return domainError
}

func (s *authService) logoutAll(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {

	existingRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, refreshToken)

	if err != nil {
		return err
	}

	if existingRefreshToken.GetUserAgent() != userAgent {
		return domainerrors.NewErrInvalidInput(
			InvalidUserAgent,
			"invalid user agent",
		)
	}

	return s.refreshTokenRepository.DeleteByUserID(
		ctx,
		existingRefreshToken.GetUserID(),
	)
}

func (s *authService) RunScheduledTasks(ctx context.Context) {
	for {
		err := s.refreshTokenRepository.DeleteExpired(ctx)
		if err != nil {
			log.Printf("authService: Error deleting expired refresh tokens: %v", err)
		} else {
			log.Println("authService: Deleted expired refresh tokens")
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(1) * time.Minute):
		}
	}
}
