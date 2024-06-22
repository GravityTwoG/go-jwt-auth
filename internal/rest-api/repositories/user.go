package repositories

import (
	"context"

	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/models"
	"go-jwt-auth/internal/rest-api/services"

	"gorm.io/gorm"
)

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) services.UserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) Create(
	ctx context.Context,
	user *entities.User,
) error {
	userModel := models.UserFromEntity(user)

	err := r.db.WithContext(ctx).Create(userModel).Error

	if err != nil {
		return err
	}
	*user = *models.UserFromModel(userModel)

	return nil
}

func (r *userRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, error) {

	userModel := models.User{}

	err := r.db.WithContext(ctx).
		Where(&models.User{Email: email}).
		First(&userModel).Error

	if err != nil {
		return nil, err
	}

	return models.UserFromModel(&userModel), nil
}
