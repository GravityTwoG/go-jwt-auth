package services

import (
	"context"
	domain_errors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/models"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

type Tokens struct {
	AccessToken  string
	RefreshToken models.RefreshToken
}

type RefreshTokenRepository interface {
	Create(ctx context.Context, refreshToken *models.RefreshToken) error

	GetByToken(ctx context.Context, token string) (*models.RefreshToken, error)

	GetByUserEmail(ctx context.Context, email string) ([]*models.RefreshToken, error)

	Delete(ctx context.Context, refreshToken *models.RefreshToken) error

	DeleteExpired(ctx context.Context) error
}

type AuthService interface {
	Register(ctx context.Context, dto *dto.RegisterDTO) (*entities.User, error)

	Login(ctx context.Context, dto *dto.LoginDTO) (*entities.User, *Tokens, error)

	RefreshTokens(ctx context.Context, refreshToken string) (*Tokens, error)

	GetUser(ctx context.Context, email string) (*entities.User, error)

	ActiveSessions(ctx context.Context, email string) ([]*models.RefreshToken, error)

	Logout(ctx context.Context, refreshToken string) error

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
) (*entities.User, error) {

	return s.userService.Register(ctx, registerDTO)
}

func (s *authService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
) (*entities.User, *Tokens, error) {

	user, err := s.userService.Login(ctx, loginDTO)
	if err != nil {
		return nil, nil, err
	}

	accessToken, err := s.newJWT(user)
	if err != nil {
		return nil, nil, err
	}

	refreshToken := &models.RefreshToken{
		UserID: user.GetId(),
		Token:  uuid.New().String(),
		TTLsec: s.refreshTokenTTLsec,
	}

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
) (*Tokens, error) {
	existingRefreshToken, err := s.refreshTokenRepository.
		GetByToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	expirationTime := existingRefreshToken.CreatedAt.
		Add(time.Duration(existingRefreshToken.TTLsec) * time.Second)

	if time.Now().After(expirationTime) {
		return nil, domain_errors.NewErrInvalidInput("refresh token expired")
	}

	// delete old token
	err = s.refreshTokenRepository.Delete(ctx, existingRefreshToken)
	if err != nil {
		return nil, err
	}

	// create new token
	newRefreshToken := &models.RefreshToken{
		UserID: existingRefreshToken.UserID,
		Token:  uuid.New().String(),
		TTLsec: s.refreshTokenTTLsec,
	}
	err = s.refreshTokenRepository.Create(ctx, newRefreshToken)
	if err != nil {
		return nil, err
	}

	user := entities.UserFromDB(
		existingRefreshToken.User.ID,
		existingRefreshToken.User.Email,
		existingRefreshToken.User.Password,
	)

	accessToken, err := s.newJWT(user)
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
) (string, error) {

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = user.GetEmail()
	claims["exp"] = time.Now().Add(time.Duration(s.jwtAccessTTLsec) * time.Second).Unix()

	tokenString, err := token.SignedString(s.jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *authService) GetUser(
	ctx context.Context,
	email string,
) (*entities.User, error) {

	return s.userService.GetByEmail(ctx, email)
}

func (s *authService) ActiveSessions(
	ctx context.Context,
	email string,
) ([]*models.RefreshToken, error) {

	return s.refreshTokenRepository.GetByUserEmail(ctx, email)
}

func (s *authService) Logout(
	ctx context.Context,
	refreshToken string,
) error {
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
