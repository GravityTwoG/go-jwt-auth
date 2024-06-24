package services

import (
	"context"
	"fmt"
	domain_errors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
)

type UserRepository interface {
	Create(
		ctx context.Context,
		user *entities.User,
	) domain_errors.ErrDomain

	GetByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domain_errors.ErrDomain)

	GetByEmail(
		ctx context.Context,
		email string,
	) (*entities.User, domain_errors.ErrDomain)
}

type UserService interface {
	Register(
		ctx context.Context,
		dto *dto.RegisterDTO,
	) (*entities.User, domain_errors.ErrDomain)

	Login(
		ctx context.Context,
		dto *dto.LoginDTO,
	) (*entities.User, domain_errors.ErrDomain)

	GetByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domain_errors.ErrDomain)

	GetByEmail(
		ctx context.Context,
		email string,
	) (*entities.User, domain_errors.ErrDomain)
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
) (*entities.User, domain_errors.ErrDomain) {

	if registerDTO.Password != registerDTO.Password2 {
		return nil, domain_errors.NewErrInvalidInput(
			"PASSWORDS_DONT_MATCH",
			"passwords don't match",
		)
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
		fmt.Printf("err: %v isNil: %v, isNotNil: %v\n", err, err == nil, err != nil)
		if err.Kind() == domain_errors.EntityAlreadyExists {
			return nil, domain_errors.NewErrInvalidInput(
				"EMAIL_ALREADY_EXISTS",
				"email already exists",
			)
		}

		return nil, err
	}

	return user, nil
}

func (s *userService) Login(
	ctx context.Context,
	loginDTO *dto.LoginDTO,
) (*entities.User, domain_errors.ErrDomain) {

	user, err := s.userRepo.GetByEmail(ctx, loginDTO.Email)
	if err != nil {
		if err.Kind() == domain_errors.EntityNotFound {
			return nil, domain_errors.NewErrInvalidInput(
				"INCORRECT_EMAIL_OR_PASSWORD",
				"incorrect email or password",
			)
		}

		return nil, err
	}

	if !user.ComparePassword(loginDTO.Password) {
		return nil, domain_errors.NewErrInvalidInput(
			"INCORRECT_EMAIL_OR_PASSWORD",
			"incorrect email or password",
		)
	}

	return user, nil
}

func (s *userService) GetByID(
	ctx context.Context,
	id uint,
) (*entities.User, domain_errors.ErrDomain) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *userService) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, domain_errors.ErrDomain) {
	return s.userRepo.GetByEmail(ctx, email)
}
