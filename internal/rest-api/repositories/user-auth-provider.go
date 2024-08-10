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

type userAuthProviderRepository struct {
	db       *gorm.DB
	txGetter *trmgorm.CtxGetter
}

func NewUserAuthProviderRepository(
	db *gorm.DB,
	txGetter *trmgorm.CtxGetter,
) services.UserAuthProviderRepository {
	return &userAuthProviderRepository{
		db:       db,
		txGetter: txGetter,
	}
}

func (r *userAuthProviderRepository) Create(
	ctx context.Context,
	userID uint,
	providerName string,
	email string,
) domainerrors.ErrDomain {

	authProvider := &models.AuthProvider{}
	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Where(&models.AuthProvider{Name: providerName}).
		First(authProvider).Error
	if err != nil {
		return database.MapGormErrors(err, "auth provider")
	}

	err = r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Preload("AuthProvider").
		Create(&models.UserAuthProvider{
			Email:          email,
			UserID:         userID,
			AuthProviderID: authProvider.ID,
		}).Error

	if err != nil {
		return database.MapGormErrors(err, "user auth provider")
	}

	return nil
}

func (r *userAuthProviderRepository) GetByUserID(
	ctx context.Context,
	userID uint,
) ([]*entities.UserAuthProvider, domainerrors.ErrDomain) {
	userAuthProviders := []*models.UserAuthProvider{}
	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Preload("AuthProvider").
		Where(&models.UserAuthProvider{UserID: userID}).
		Find(&userAuthProviders).Error

	if err != nil {
		return nil, database.MapGormErrors(err, "user auth provider")
	}

	entities := make([]*entities.UserAuthProvider, 0, len(userAuthProviders))
	for i := 0; i < len(userAuthProviders); i++ {
		entities = append(
			entities,
			models.UserAuthProviderFromModel(userAuthProviders[i]),
		)
	}

	return entities, nil
}

func (r *userAuthProviderRepository) GetByEmailAndProvider(
	ctx context.Context,
	email string,
	providerName string,
) (*entities.UserAuthProvider, domainerrors.ErrDomain) {

	authProvider := &models.AuthProvider{}
	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Where(&models.AuthProvider{Name: providerName}).
		First(authProvider).Error
	if err != nil {
		return nil, database.MapGormErrors(err, "auth provider")
	}

	userAuthProvider := &models.UserAuthProvider{}
	err = r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Where(&models.UserAuthProvider{
			Email:          email,
			AuthProviderID: authProvider.ID,
		}).
		First(userAuthProvider).Error

	if err != nil {
		return nil, database.MapGormErrors(err, "user auth provider")
	}

	return models.UserAuthProviderFromModel(userAuthProvider), nil
}

func (r *userAuthProviderRepository) Delete(
	ctx context.Context,
	userAuthProvider *entities.UserAuthProvider,
) domainerrors.ErrDomain {

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Delete(userAuthProvider).Error

	if err != nil {
		return database.MapGormErrors(err, "user auth provider")
	}

	return nil
}
