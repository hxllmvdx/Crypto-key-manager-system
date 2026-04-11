package repository

import (
	"context"
	"errors"
	"fmt"
	"github.com/hxllmvdx/Crypto-key-management-system/pkg/domain"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/usererrors"
	"gorm.io/gorm"
)

type UserRepository interface {
	Create(ctx context.Context, login, password string) error
	GetByLogin(ctx context.Context, login string) (*domain.User, error)
	Update(ctx context.Context, login, password string) error
	Delete(ctx context.Context, login string) error
}

type UserRepo struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) UserRepository {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, login, password string) error {
	user := domain.User{Username: login}

	err := user.SetPassword(password)
	if err != nil {
		return err
	}

	return r.db.WithContext(ctx).Create(&user).Error
}

func (r *UserRepo) GetByLogin(ctx context.Context, login string) (*domain.User, error) {
	var user domain.User
	result := r.db.WithContext(ctx).
		Where("username = ?", login).
		First(&user)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("get user by login: %w", usererrors.ErrNotFound)
		}
		return nil, result.Error
	}

	return &user, nil
}

func (r *UserRepo) Update(ctx context.Context, login, password string) error {
	user, err := r.GetByLogin(ctx, login)
	if err != nil {
		return err
	}

	if err := user.CheckPassword(password); err != nil {
		return err
	}

	if err := user.SetPassword(password); err != nil {
		return err
	}

	return r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", user.ID).
		Update("password", user.PasswordHash).
		Error
}

func (r *UserRepo) Delete(ctx context.Context, login string) error {
	return r.db.WithContext(ctx).Delete(&domain.User{}, "username = ?", login).Error
}
