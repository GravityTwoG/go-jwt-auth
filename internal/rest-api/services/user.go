package services

import (
	"context"
	"fmt"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
)

type UserRepository interface {
	Create(ctx context.Context, user *entities.User) error

	GetByEmail(ctx context.Context, email string) (*entities.User, error)
}

type UserService interface {
	Register(ctx context.Context, dto *dto.RegisterDTO) (*entities.User, error)

	Login(ctx context.Context, dto *dto.LoginDTO) (*entities.User, error)

	GetByEmail(ctx context.Context, email string) (*entities.User, error)
}

type userService struct {
	userRepo UserRepository
}

func NewUserService(
	userRepo UserRepository,
) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) Register(
	ctx context.Context,
	registerDTO *dto.RegisterDTO,
) (*entities.User, error) {

	if registerDTO.Password != registerDTO.Password2 {
		return nil, fmt.Errorf("PASSWORDS_DONT_MATCH")
	}

	user, err := entities.NewUser(
		registerDTO.Email,
		registerDTO.Password,
	)
	if err != nil {
		return nil, err
	}

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
) (*entities.User, error) {

	user, err := s.userRepo.GetByEmail(ctx, loginDTO.Email)
	if err != nil {
		if err.Error() == "record not found" {
			return nil, fmt.Errorf("INCORRECT_EMAIL_OR_PASSWORD")
		}

		return nil, err
	}

	if !user.ComparePassword(loginDTO.Password) {
		return nil, fmt.Errorf("INCORRECT_EMAIL_OR_PASSWORD")
	}

	return user, nil
}

func (s *userService) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, error) {
	return s.userRepo.GetByEmail(ctx, email)
}
