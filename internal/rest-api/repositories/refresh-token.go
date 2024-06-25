package repositories

import (
	"context"
	"go-jwt-auth/internal/rest-api/database"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/entities"
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
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {

	model := models.RefreshTokenFromEntity(refreshToken)

	err := r.db.WithContext(ctx).Preload("User").Create(model).Error
	if err != nil {
		return database.MapGormErrors(err, "refresh token")
	}
	*refreshToken = *models.RefreshTokenFromModel(model)
	return nil
}

func (r *refreshTokenRepository) GetByToken(
	ctx context.Context,
	token string,
) (*entities.RefreshToken, domainerrors.ErrDomain) {

	refreshToken := &models.RefreshToken{}
	err := r.db.WithContext(ctx).
		Preload("User").
		Where(&models.RefreshToken{Token: token}).
		First(refreshToken).Error

	if err != nil {
		return nil, database.MapGormErrors(err, "refresh token")
	}

	return models.RefreshTokenFromModel(refreshToken), nil
}

func (r *refreshTokenRepository) GetByUserEmail(
	ctx context.Context,
	email string,
) ([]*entities.RefreshToken, domainerrors.ErrDomain) {

	refreshTokens := []*models.RefreshToken{}
	err := r.db.WithContext(ctx).
		Preload("User").
		Where(&models.RefreshToken{User: models.User{Email: email}}).
		Find(&refreshTokens).Error
	if err != nil {
		return nil, database.MapGormErrors(err, "refresh token")
	}

	entities := make([]*entities.RefreshToken, len(refreshTokens))
	for i := 0; i < len(refreshTokens); i++ {
		entities[i] = models.RefreshTokenFromModel(refreshTokens[i])
	}

	return entities, nil
}

func (r *refreshTokenRepository) Delete(
	ctx context.Context,
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {

	model := models.RefreshTokenFromEntity(refreshToken)
	err := r.db.WithContext(ctx).Delete(model).Error
	if err != nil {
		return database.MapGormErrors(err, "refresh token")
	}
	return nil
}

func (r *refreshTokenRepository) DeleteByUserID(
	ctx context.Context,
	userID uint,
) domainerrors.ErrDomain {

	err := r.db.WithContext(ctx).
		Where(&models.RefreshToken{UserID: userID}).
		Delete(&models.RefreshToken{}).
		Error

	if err != nil {
		return database.MapGormErrors(err, "refresh-token")
	}

	return nil
}

func (r *refreshTokenRepository) DeleteExpired(
	ctx context.Context,
) domainerrors.ErrDomain {

	err := r.db.WithContext(ctx).
		Where("created_at + interval '1 second' * ttlsec < now()").
		Delete(&models.RefreshToken{}).
		Error

	if err != nil {
		return database.MapGormErrors(err, "refresh token")
	}

	return nil
}
