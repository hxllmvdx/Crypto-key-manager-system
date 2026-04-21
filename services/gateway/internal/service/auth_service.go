package service

import (
	"context"
	"errors"
	"time"

	jwtManager "github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/jwt"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/repository"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/session"
)

type AuthResult struct {
	AccessToken  string
	RefreshToken string
}

type AuthService interface {
	UserLogin(ctx context.Context, userName, password string, timeNow time.Time) (AuthResult, error)
	UserRegister(ctx context.Context, userName, password string, timeNow time.Time) (AuthResult, error)
	UserRefresh(ctx context.Context, refreshToken string, timeNow time.Time) (AuthResult, error)
}

type authService struct {
	repo         repository.UserRepository
	sessionStore session.SessionStore
	tokenManager jwtManager.TokenManager
}

func NewAuthService(repo repository.UserRepository, sessionStore session.SessionStore, tokenManager jwtManager.TokenManager) AuthService {
	return &authService{
		repo:         repo,
		sessionStore: sessionStore,
		tokenManager: tokenManager,
	}
}

func (s *authService) UserRefresh(ctx context.Context, refreshToken string, timeNow time.Time) (AuthResult, error) {
	if refreshToken == "" {
		return AuthResult{}, errors.New("invalid refresh token")
	}

	userID, err := s.sessionStore.GetUserIDByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, session.ErrTokenNotFound) {
			return AuthResult{}, errors.New("invalid refresh token")
		}
		return AuthResult{}, err
	}

	_, err = s.repo.GetByID(ctx, userID)
	if err != nil {
		return AuthResult{}, err
	}

	newJWTToken, err := s.tokenManager.GenerateAccessToken(userID, timeNow)
	if err != nil {
		return AuthResult{}, err
	}

	newRefreshToken, err := s.tokenManager.GenerateRefreshToken(userID, timeNow)
	if err != nil {
		return AuthResult{}, err
	}

	if err := s.sessionStore.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return AuthResult{}, err
	}

	if err := s.sessionStore.SaveRefreshToken(ctx, userID, newRefreshToken); err != nil {
		return AuthResult{}, err
	}

	return AuthResult{
		AccessToken:  newJWTToken,
		RefreshToken: newRefreshToken,
	}, nil
}
