package services

import (
	"context"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AuthService interface {
	Register(ctx context.Context, dto *dto.RegisterDTO) (*entities.User, error)

	Login(ctx context.Context, dto *dto.LoginDTO) (*entities.User, string, error)
}

type authService struct {
	userService UserService

	jwtSecretKey          []byte
	tokenExpirationMillis int64
}

func NewAuthService(
	userService UserService,
	jwtSecretKey string,
	tokenExpirationMillis int64,
) AuthService {
	return &authService{
		userService: userService,

		jwtSecretKey:          []byte(jwtSecretKey),
		tokenExpirationMillis: tokenExpirationMillis,
	}
}

func (s *authService) Register(ctx context.Context, registerDTO *dto.RegisterDTO) (*entities.User, error) {

	return s.userService.Register(ctx, registerDTO)
}

func (s *authService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
) (*entities.User, string, error) {

	user, err := s.userService.Login(ctx, loginDTO)
	if err != nil {
		return nil, "", err
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = user.GetEmail()
	claims["exp"] = time.Now().Add(time.Duration(s.tokenExpirationMillis) * time.Millisecond).Unix()

	tokenString, err := token.SignedString(s.jwtSecretKey)
	if err != nil {
		return nil, "", err
	}

	return user, tokenString, nil
}
