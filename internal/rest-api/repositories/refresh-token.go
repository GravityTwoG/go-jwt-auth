package repositories

import (
	"context"
	"go-jwt-auth/internal/rest-api/models"
	"go-jwt-auth/internal/rest-api/services"

	"gorm.io/gorm"
)

type refreshTokenRepository struct {
	db *gorm.DB
}

func NewRefreshTokenRepository(db *gorm.DB) services.RefreshTokenRepository {
	return &refreshTokenRepository{
		db: db,
	}
}

func (r *refreshTokenRepository) Create(
	ctx context.Context,
	refreshToken *models.RefreshToken,
) error {

	err := r.db.WithContext(ctx).Create(refreshToken).Error
	if err != nil {
		return err
	}
	return nil
}

func (r *refreshTokenRepository) GetByToken(
	ctx context.Context,
	token string,
) (*models.RefreshToken, error) {

	refreshToken := &models.RefreshToken{}
	err := r.db.WithContext(ctx).
		Preload("User").
		Where(&models.RefreshToken{Token: token}).
		First(refreshToken).Error

	if err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func (r *refreshTokenRepository) GetByUserEmail(
	ctx context.Context,
	email string,
) ([]*models.RefreshToken, error) {

	refreshTokens := []*models.RefreshToken{}
	err := r.db.WithContext(ctx).
		Preload("User").
		Where(&models.RefreshToken{User: models.User{Email: email}}).
		Find(&refreshTokens).Error
	if err != nil {
		return nil, err
	}

	return refreshTokens, nil
}

func (r *refreshTokenRepository) Delete(
	ctx context.Context,
	refreshToken *models.RefreshToken,
) error {

	err := r.db.WithContext(ctx).Delete(refreshToken).Error
	if err != nil {
		return err
	}
	return nil
}

func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("created_at + interval '1 second' * ttlsec < now()").
		Delete(&models.RefreshToken{}).
		Error
}
