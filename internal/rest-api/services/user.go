package services

import (
	"context"
	"fmt"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/dto"
	"go-jwt-auth/internal/rest-api/entities"
)

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

type UserService interface {
	Register(
		ctx context.Context,
		dto *dto.RegisterDTO,
	) (*entities.User, domainerrors.ErrDomain)

	Login(
		ctx context.Context,
		dto *dto.LoginDTO,
	) (*entities.User, domainerrors.ErrDomain)

	GetByID(
		ctx context.Context,
		id uint,
	) (*entities.User, domainerrors.ErrDomain)

	GetByEmail(
		ctx context.Context,
		email string,
	) (*entities.User, domainerrors.ErrDomain)
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
) (*entities.User, domainerrors.ErrDomain) {

	if registerDTO.Password != registerDTO.Password2 {
		return nil, domainerrors.NewErrInvalidInput(
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
		if err.Kind() == domainerrors.EntityAlreadyExists {
			return nil, domainerrors.NewErrInvalidInput(
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
) (*entities.User, domainerrors.ErrDomain) {

	user, err := s.userRepo.GetByEmail(ctx, loginDTO.Email)
	if err != nil {
		if err.Kind() == domainerrors.EntityNotFound {
			return nil, domainerrors.NewErrInvalidInput(
				"INCORRECT_EMAIL_OR_PASSWORD",
				"incorrect email or password",
			)
		}

		return nil, err
	}

	if !user.ComparePassword(loginDTO.Password) {
		return nil, domainerrors.NewErrInvalidInput(
			"INCORRECT_EMAIL_OR_PASSWORD",
			"incorrect email or password",
		)
	}

	return user, nil
}

func (s *userService) GetByID(
	ctx context.Context,
	id uint,
) (*entities.User, domainerrors.ErrDomain) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *userService) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, domainerrors.ErrDomain) {
	return s.userRepo.GetByEmail(ctx, email)
}
