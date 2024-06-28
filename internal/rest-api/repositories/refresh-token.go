package repositories

import (
	"context"
	"go-jwt-auth/internal/rest-api/database"
	domainerrors "go-jwt-auth/internal/rest-api/domain-errors"
	"go-jwt-auth/internal/rest-api/entities"
	"go-jwt-auth/internal/rest-api/models"
	"go-jwt-auth/internal/rest-api/services"

	trmgorm "github.com/avito-tech/go-transaction-manager/drivers/gorm/v2"
	"gorm.io/gorm"
)

type refreshTokenRepository struct {
	db       *gorm.DB
	txGetter *trmgorm.CtxGetter
}

func NewRefreshTokenRepository(
	db *gorm.DB,
	txGetter *trmgorm.CtxGetter,
) services.RefreshTokenRepository {
	return &refreshTokenRepository{
		db:       db,
		txGetter: txGetter,
	}
}

func (r *refreshTokenRepository) Create(
	ctx context.Context,
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {

	model := models.RefreshTokenFromEntity(refreshToken)

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Preload("User").
		Create(model).Error

	if err != nil {
		return database.MapGormErrors(err, "refresh token")
	}
	*refreshToken = *models.RefreshTokenFromModel(model)
	return nil
}

func (r *refreshTokenRepository) Update(
	ctx context.Context,
	refreshToken *entities.RefreshToken,
) domainerrors.ErrDomain {
	model := models.RefreshTokenFromEntity(refreshToken)

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Save(model).Error
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
	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Preload("User").
		Where(&models.RefreshToken{Token: token}).
		First(refreshToken).Error

	if err != nil {
		return nil, database.MapGormErrors(err, "refresh token")
	}

	return models.RefreshTokenFromModel(refreshToken), nil
}

func (r *refreshTokenRepository) GetByUserID(
	ctx context.Context,
	id uint,
) ([]*entities.RefreshToken, domainerrors.ErrDomain) {

	refreshTokens := []*models.RefreshToken{}
	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Preload("User").
		Where(&models.RefreshToken{UserID: id}).
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
	err := r.txGetter.DefaultTrOrDB(ctx, r.db).Delete(model).Error
	if err != nil {
		return database.MapGormErrors(err, "refresh token")
	}
	return nil
}

func (r *refreshTokenRepository) DeleteByUserID(
	ctx context.Context,
	userID uint,
) domainerrors.ErrDomain {

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
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

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Where("created_at + interval '1 second' * ttlsec < now()").
		Delete(&models.RefreshToken{}).
		Error

	if err != nil {
		return database.MapGormErrors(err, "refresh token")
	}

	return nil
}
