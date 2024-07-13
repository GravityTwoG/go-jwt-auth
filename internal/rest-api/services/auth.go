package services

import (
	"context"
	"crypto/rsa"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"log"
	"time"

	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
)

const InvalidRefreshToken = "INVALID_REFRESH_TOKEN"
const RefreshTokenExpired = "REFRESH_TOKEN_EXPIRED"
const RefreshTokenNotFound = "REFRESH_TOKEN_NOT_FOUND"
const InvalidUserAgent = "INVALID_USER_AGENT"
const InvalidFingerPrint = "INVALID_FINGER_PRINT"

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

type AuthService interface {
	Register(
		ctx context.Context,
		dto *dto.RegisterDTO,
	) (*entities.User, domainerrors.ErrDomain)

	Login(
		ctx context.Context,
		dto *dto.LoginDTO,
		ip string,
		userAgent string,
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

	userService UserService

	refreshTokenRepository RefreshTokenRepository

	jwtPrivateKey      *rsa.PrivateKey
	jwtPublicKey       *rsa.PublicKey
	accessTokenTTLsec  int
	refreshTokenTTLsec int
}

func NewAuthService(
	trManager *manager.Manager,
	userService UserService,
	refreshTokenRepository RefreshTokenRepository,
	jwtPrivateKey *rsa.PrivateKey,
	jwtAccessTTL int,
	refreshTokenTTL int,
) AuthService {

	jwtPrivateKey.Public()

	return &authService{
		trManager: trManager,

		userService: userService,

		refreshTokenRepository: refreshTokenRepository,

		jwtPrivateKey:      jwtPrivateKey,
		jwtPublicKey:       &jwtPrivateKey.PublicKey,
		accessTokenTTLsec:  jwtAccessTTL,
		refreshTokenTTLsec: refreshTokenTTL,
	}
}

func (s *authService) Register(
	ctx context.Context,
	registerDTO *dto.RegisterDTO,
) (*entities.User, domainerrors.ErrDomain) {

	return s.userService.Register(ctx, registerDTO)
}

func (s *authService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
	ip string,
	userAgent string,
) (*entities.User, *Tokens, domainerrors.ErrDomain) {

	user, err := s.userService.Login(ctx, loginDTO)
	if err != nil {
		return nil, nil, err
	}

	accessToken, err := newJWT(
		user,
		s.accessTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err := newJWT(
		user,
		s.refreshTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	refreshTokenEntity := entities.NewRefreshToken(
		refreshToken,
		user.GetID(),
		s.refreshTokenTTLsec,
		ip,
		userAgent,
		loginDTO.FingerPrint,
	)

	err = s.refreshTokenRepository.Create(ctx, refreshTokenEntity)
	if err != nil {
		return nil, nil, err
	}

	return user, &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *refreshTokenEntity,
	}, nil
}

func (s *authService) RefreshTokens(
	ctx context.Context,
	dto *RefreshTokensDTO,
) (*Tokens, domainerrors.ErrDomain) {

	tokenClaims, jwtErr := ParseJWT(dto.OldToken, s.jwtPublicKey)
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
	accessToken, err := newJWT(
		refreshTokenEntity.GetUser(),
		s.accessTokenTTLsec,
		s.jwtPrivateKey,
	)
	if err != nil {
		return nil, err
	}

	// create new refresh token
	newRefreshToken, err := newJWT(
		refreshTokenEntity.GetUser(),
		s.refreshTokenTTLsec,
		s.jwtPrivateKey,
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

	return s.userService.GetByID(ctx, id)
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
