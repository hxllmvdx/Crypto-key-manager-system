package service

import (
	"context"

	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/repository"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/session"
)

type AuthResult struct {
	AccessToken  string
	RefreshToken string
}

type AuthService interface {
	UserLogin(ctx context.Context, userName, password string) (AuthResult, error)
	UserRegister(ctx context.Context, userName, password string) (AuthResult, error)
	UserRefresh(ctx context.Context, refreshToken string) (AuthResult, error)
}

type authService struct {
	repo         *repository.UserRepository
	sessionStore *session.SessionStore
}

func NewAuthService(repo *repository.UserRepository, sessionStore *session.SessionStore) AuthService {
	return &authService{
		repo:         repo,
		sessionStore: sessionStore,
	}
}
