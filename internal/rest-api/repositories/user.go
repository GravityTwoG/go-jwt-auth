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

type userRepository struct {
	db       *gorm.DB
	txGetter *trmgorm.CtxGetter
}

func NewUserRepository(
	db *gorm.DB,
	txGetter *trmgorm.CtxGetter,
) services.UserRepository {
	return &userRepository{
		db:       db,
		txGetter: txGetter,
	}
}

func (r *userRepository) Create(
	ctx context.Context,
	user *entities.User,
) domainerrors.ErrDomain {

	userModel := models.UserFromEntity(user)

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Create(userModel).Error

	if err != nil {
		return database.MapGormErrors(err, "user")
	}
	*user = *models.UserFromModel(userModel)

	return nil
}

func (r *userRepository) GetByID(
	ctx context.Context,
	id uint,
) (*entities.User, domainerrors.ErrDomain) {
	userModel := models.User{}

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Where(&models.User{ID: id}).
		First(&userModel).Error

	if err != nil {
		return nil, database.MapGormErrors(err, "user")
	}

	return models.UserFromModel(&userModel), nil
}

func (r *userRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*entities.User, domainerrors.ErrDomain) {

	userModel := models.User{}

	err := r.txGetter.
		DefaultTrOrDB(ctx, r.db).
		Where(&models.User{Email: email}).
		First(&userModel).Error

	if err != nil {
		return nil, database.MapGormErrors(err, "user")
	}

	return models.UserFromModel(&userModel), nil
}

func (r *userRepository) DeleteByID(
	ctx context.Context,
	id uint,
) domainerrors.ErrDomain {

	tx := r.txGetter.DefaultTrOrDB(ctx, r.db).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	err := tx.
		Unscoped().
		Where(&models.RefreshToken{UserID: id}).
		Delete(&models.RefreshToken{}).Error
	if err != nil {
		tx.Rollback()
		return database.MapGormErrors(err, "refresh token")
	}

	err = tx.
		Unscoped().
		Delete(&models.UserAuthProvider{}, "user_id = ?", id).
		Error

	if err != nil {
		tx.Rollback()
		return database.MapGormErrors(err, "user auth provider")
	}

	err = tx.
		Unscoped().
		Where(&models.User{ID: id}).
		Delete(&models.User{}).Error

	if err != nil {
		tx.Rollback()
		return database.MapGormErrors(err, "user")
	}

	err = tx.Commit().Error
	if err != nil {
		return database.MapGormErrors(err, "transaction")
	}

	return nil
}
