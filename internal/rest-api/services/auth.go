package services

import (
	"context"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Tokens struct {
	AccessToken  string
	RefreshToken entities.RefreshToken
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

	GetByUserEmail(
		ctx context.Context,
		email string,
	) ([]*entities.RefreshToken, domainerrors.ErrDomain)

	Delete(
		ctx context.Context,
		refreshToken *entities.RefreshToken,
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
	) (*entities.User, *Tokens, domainerrors.ErrDomain)

	RefreshTokens(
		ctx context.Context,
		refreshToken string,
	) (*Tokens, domainerrors.ErrDomain)

	GetUserByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domainerrors.ErrDomain)

	ActiveSessions(
		ctx context.Context,
		email string,
	) ([]*entities.RefreshToken, domainerrors.ErrDomain)

	Logout(
		ctx context.Context,
		refreshToken string,
	) domainerrors.ErrDomain

	RunScheduledTasks(ctx context.Context)
}

type authService struct {
	userService UserService

	refreshTokenRepository RefreshTokenRepository

	jwtSecretKey       []byte
	jwtAccessTTLsec    int
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
		jwtAccessTTLsec:    jwtAccessTTL,
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
) (*entities.User, *Tokens, domainerrors.ErrDomain) {

	user, err := s.userService.Login(ctx, loginDTO)
	if err != nil {
		return nil, nil, err
	}

	accessToken, err := s.newJWT(user)
	if err != nil {
		return nil, nil, err
	}

	refreshToken := entities.NewRefreshToken(
		user.GetId(),
		s.refreshTokenTTLsec,
	)

	err = s.refreshTokenRepository.Create(ctx, refreshToken)
	if err != nil {
		return nil, nil, err
	}

	tokens := &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *refreshToken,
	}

	return user, tokens, nil
}

func (s *authService) RefreshTokens(
	ctx context.Context,
	refreshToken string,
) (*Tokens, domainerrors.ErrDomain) {
	existingRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if existingRefreshToken.Expired() {
		return nil, domainerrors.NewErrInvalidInput(
			"REFRESH_TOKEN_EXPIRED",
			"refresh token expired",
		)
	}

	// create new token
	newRefreshToken := entities.NewRefreshToken(
		existingRefreshToken.GetUserId(),
		s.refreshTokenTTLsec,
	)
	err = s.refreshTokenRepository.Create(ctx, newRefreshToken)
	if err != nil {
		return nil, err
	}

	// delete old token
	err = s.refreshTokenRepository.Delete(ctx, existingRefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.newJWT(existingRefreshToken.GetUser())
	if err != nil {
		return nil, err
	}

	tokens := &Tokens{
		AccessToken:  accessToken,
		RefreshToken: *newRefreshToken,
	}

	return tokens, nil
}

func (s *authService) newJWT(
	user *entities.User,
) (string, domainerrors.ErrDomain) {

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.GetId()
	claims["email"] = user.GetEmail()
	claims["exp"] = time.Now().Add(time.Duration(s.jwtAccessTTLsec) * time.Second).Unix()

	tokenString, err := token.SignedString(s.jwtSecretKey)
	if err != nil {
		return "", domainerrors.NewErrUnknown(err)
	}

	return tokenString, nil
}

func (s *authService) GetUserByID(
	ctx context.Context,
	id uint,
) (*entities.User, domainerrors.ErrDomain) {

	return s.userService.GetByID(ctx, id)
}

func (s *authService) ActiveSessions(
	ctx context.Context,
	email string,
) ([]*entities.RefreshToken, domainerrors.ErrDomain) {

	return s.refreshTokenRepository.GetByUserEmail(ctx, email)
}

func (s *authService) Logout(
	ctx context.Context,
	refreshToken string,
) domainerrors.ErrDomain {
	model, err := s.refreshTokenRepository.GetByToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	return s.refreshTokenRepository.Delete(ctx, model)
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
