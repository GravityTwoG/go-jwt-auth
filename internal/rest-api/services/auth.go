package services

import (
	"context"
	"errors"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
	userService UserService

	refreshTokenRepository RefreshTokenRepository

	jwtSecretKey       []byte
	accessTokenTTLsec  int
	refreshTokenTTLsec int
}

func NewAuthService(
	userService UserService,
	refreshTokenRepository RefreshTokenRepository,
	jwtSecretKey string,
	jwtAccessTTL int,
	refreshTokenTTL int,
) AuthService {

	return &authService{
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
		user.GetId(),
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

	oldRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, dto.OldToken)

	if err != nil {
		// Token with valid signature and expiration provided,
		// but this token doesn't exist in DB.
		// Maybe was stolen and deleted by another person.
		if err.Kind() == domainerrors.EntityNotFound {
			s.refreshTokenRepository.DeleteByUserID(
				ctx,
				tokenClaims.ID,
			)

			return nil, domainerrors.NewErrEntityNotFound(
				"REFRESH_TOKEN_NOT_FOUND",
				"refresh token not found. All refresh tokens were deleted",
			)
		}

		return nil, err
	}

	if oldRefreshToken.GetUserAgent() != dto.UserAgent {
		return nil, domainerrors.NewErrInvalidInput(
			InvalidUserAgent,
			"invalid user agent",
		)
	}

	if oldRefreshToken.Expired() {
		return nil, domainerrors.NewErrInvalidInput(
			RefreshTokenExpired,
			"refresh token expired",
		)
	}

	// create new access token
	accessToken, err := newJWT(
		oldRefreshToken.GetUser(),
		s.accessTokenTTLsec,
		s.jwtSecretKey,
	)
	if err != nil {
		return nil, err
	}

	// create new refresh token
	newRefreshToken, err := newJWT(
		oldRefreshToken.GetUser(),
		s.refreshTokenTTLsec,
		s.jwtSecretKey,
	)
	if err != nil {
		return nil, err
	}

	newRefreshTokenEntity := entities.NewRefreshToken(
		newRefreshToken,
		oldRefreshToken.GetUserId(),
		s.refreshTokenTTLsec,
		dto.IP,
		dto.UserAgent,
	)
	err = s.refreshTokenRepository.Create(ctx, newRefreshTokenEntity)
	if err != nil {
		return nil, err
	}

	// delete old token
	err = s.refreshTokenRepository.Delete(ctx, oldRefreshToken)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *newRefreshTokenEntity,
	}, nil
}

func newJWT(
	user *entities.User,
	ttlSec int,
	secretKey []byte,
) (string, domainerrors.ErrDomain) {

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.GetId()
	claims["email"] = user.GetEmail()
	claims["exp"] = time.
		Now().
		Add(time.Duration(ttlSec) * time.Second).
		Unix()

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return tokenString, nil
}

type TokenClaims struct {
	ID    uint
	Email string
}

func ParseJWT(tokenString string, jwtSecretKey []byte) (*TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what we expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, err
	}

	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		return nil, errors.New("token-expired")
	}

	return &TokenClaims{
		ID:    uint(claims["id"].(float64)),
		Email: claims["email"].(string),
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

	return s.refreshTokenRepository.Delete(ctx, existingRefreshToken)
}

func (s *authService) LogoutAll(
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
		existingRefreshToken.GetUserId(),
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
