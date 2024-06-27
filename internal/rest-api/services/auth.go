package services

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"log"
	"time"

	"github.com/avito-tech/go-transaction-manager/trm/v2/manager"
)

const InvalidRefreshToken = "INVALID_REFRESH_TOKEN"
const RefreshTokenExpired = "REFRESH_TOKEN_EXPIRED"
const InvalidUserAgent = "INVALID_USER_AGENT"

type Tokens struct {
	AccessToken  string
	RefreshToken entities.RefreshToken
}

type RefreshTokensDTO struct {
	OldToken  string
	IP        string
	UserAgent string
}

type RefreshTokenRepository interface {
	Create(
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

	jwtSecretKey       []byte
	accessTokenTTLsec  int
	refreshTokenTTLsec int
}

func NewAuthService(
	trManager *manager.Manager,
	userService UserService,
	refreshTokenRepository RefreshTokenRepository,
	jwtSecretKey string,
	jwtAccessTTL int,
	refreshTokenTTL int,
) AuthService {

	return &authService{
		trManager: trManager,

		userService: userService,

		refreshTokenRepository: refreshTokenRepository,

		jwtSecretKey:       []byte(jwtSecretKey),
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
		s.jwtSecretKey,
	)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err := newJWT(
		user,
		s.refreshTokenTTLsec,
		s.jwtSecretKey,
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

	tokenClaims, jwtErr := ParseJWT(dto.OldToken, s.jwtSecretKey)
	if jwtErr != nil {
		return nil, domainerrors.NewErrInvalidInput(
			InvalidRefreshToken,
			"invalid or expired refresh token",
		)
	}

	var tokens *Tokens = nil
	var domainError domainerrors.ErrDomain = nil

	s.trManager.Do(ctx, func(ctx context.Context) error {
		oldRefreshToken, err := s.refreshTokenRepository.
			GetByToken(ctx, dto.OldToken)

		// Token with valid signature and expiration provided,
		// but this token doesn't exist in DB.
		// Maybe was stolen and deleted by another person.
		if err != nil && err.Kind() == domainerrors.EntityNotFound {
			s.refreshTokenRepository.DeleteByUserID(
				ctx,
				tokenClaims.ID,
			)

			domainError = domainerrors.NewErrEntityNotFound(
				"REFRESH_TOKEN_NOT_FOUND",
				"refresh token not found. All refresh tokens were deleted",
			)
			return domainError
		}
		if err != nil {
			domainError = err
			return domainError
		}

		if oldRefreshToken.GetUserAgent() != dto.UserAgent {
			s.refreshTokenRepository.DeleteByUserID(
				ctx,
				tokenClaims.ID,
			)

			domainError = domainerrors.NewErrEntityNotFound(
				InvalidUserAgent,
				"invalid user agent. All refresh tokens were deleted",
			)
			return domainError
		}

		if oldRefreshToken.Expired() {
			domainError = domainerrors.NewErrInvalidInput(
				RefreshTokenExpired,
				"refresh token expired",
			)
			return domainError
		}

		// create new access token
		accessToken, err := newJWT(
			oldRefreshToken.GetUser(),
			s.accessTokenTTLsec,
			s.jwtSecretKey,
		)
		if err != nil {
			domainError = err
			return domainError
		}

		// create new refresh token
		newRefreshToken, err := newJWT(
			oldRefreshToken.GetUser(),
			s.refreshTokenTTLsec,
			s.jwtSecretKey,
		)
		if err != nil {
			domainError = err
			return domainError
		}

		newRefreshTokenEntity := entities.NewRefreshToken(
			newRefreshToken,
			oldRefreshToken.GetUserID(),
			s.refreshTokenTTLsec,
			dto.IP,
			dto.UserAgent,
		)
		err = s.refreshTokenRepository.Create(ctx, newRefreshTokenEntity)
		if err != nil {
			domainError = err
			return domainError
		}

		// delete old token
		err = s.refreshTokenRepository.Delete(ctx, oldRefreshToken)
		if err != nil {
			domainError = err
			return domainError
		}

		tokens = &Tokens{
			AccessToken:  accessToken,
			RefreshToken: *newRefreshTokenEntity,
		}
		return nil
	})

	return tokens, domainError
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

	s.trManager.Do(ctx, func(ctx context.Context) error {
		existingRefreshToken, err := s.refreshTokenRepository.
			GetByToken(ctx, refreshToken)
		if err != nil {
			domainError = err
			return domainError
		}

		if existingRefreshToken.GetUserAgent() != userAgent {
			domainError = domainerrors.NewErrInvalidInput(
				InvalidUserAgent,
				"invalid user agent",
			)
			return domainError
		}

		domainError = s.refreshTokenRepository.Delete(ctx, existingRefreshToken)
		return domainError
	})

	return domainError
}

func (s *authService) LogoutAll(
	ctx context.Context,
	refreshToken string,
	userAgent string,
) domainerrors.ErrDomain {
	var domainError domainerrors.ErrDomain = nil

	s.trManager.Do(ctx, func(ctx context.Context) error {

		existingRefreshToken, err := s.refreshTokenRepository.
			GetByToken(ctx, refreshToken)

		if err != nil {
			domainError = err
			return domainError
		}

		if existingRefreshToken.GetUserAgent() != userAgent {
			domainError = domainerrors.NewErrInvalidInput(
				InvalidUserAgent,
				"invalid user agent",
			)
			return domainError
		}

		domainError = s.refreshTokenRepository.DeleteByUserID(
			ctx,
			existingRefreshToken.GetUserID(),
		)
		return domainError
	})

	return domainError
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
