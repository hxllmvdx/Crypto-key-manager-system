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
	UserLogin(ctx context.Context, username, password string, timeNow time.Time) (AuthResult, error)
	UserRegister(ctx context.Context, username, password string, timeNow time.Time) (AuthResult, error)
	UserRefresh(ctx context.Context, refreshToken string, timeNow time.Time) (AuthResult, error)
}

type authService struct {
	repo         repository.UserRepository
	sessionStore session.SessionStore
	tokenManager jwtManager.TokenManager
}

func NewAuthService(repo repository.UserRepository, sessionStore session.SessionStore, jwtManager jwtManager.TokenManager) AuthService {
	return &authService{
		repo:         repo,
		sessionStore: sessionStore,
		tokenManager: jwtManager,
	}
}

func (s *authService) UserLogin(ctx context.Context, username, password string, timeNow time.Time) (AuthResult, error) {
	if username == "" {
		return AuthResult{}, errors.New("username is empty")
	}
	if password == "" {
		return AuthResult{}, errors.New("password is empty")
	}

	user, err := s.repo.GetByLogin(ctx, username)
	if err != nil {
		return AuthResult{}, err
	}

	if err := user.CheckPassword(password); err != nil {
		return AuthResult{}, errors.New("invalid credentials")
	}

	tokenAccessString, err := s.tokenManager.GenerateAccessToken(user.ID, timeNow)
	if err != nil {
		return AuthResult{}, err
	}

	tokenRefreshString, err := s.tokenManager.GenerateRefreshToken(user.ID, timeNow)
	if err != nil {
		return AuthResult{}, err
	}
	if err := s.sessionStore.SaveRefreshToken(ctx, user.ID, tokenRefreshString); err != nil {
		return AuthResult{}, err
	}

	return AuthResult{
		AccessToken:  tokenAccessString,
		RefreshToken: tokenRefreshString,
	}, nil
}

func (s *authService) UserRegister(ctx context.Context, username, password string, timeNow time.Time) (AuthResult, error) {
	if username == "" {
		return AuthResult{}, errors.New("username is empty")
	}
	if password == "" {
		return AuthResult{}, errors.New("password is empty")
	}

	err := s.repo.Create(ctx, username, password)
	if err != nil {
		return AuthResult{}, err
	}

	user, err := s.repo.GetByLogin(ctx, username)
	if err != nil {
		return AuthResult{}, err
	}

	tokenAccessString, err := s.tokenManager.GenerateAccessToken(user.ID, timeNow)
	if err != nil {
		return AuthResult{}, err
	}

	tokenRefreshString, err := s.tokenManager.GenerateRefreshToken(user.ID, timeNow)
	if err != nil {
		return AuthResult{}, err
	}
	if err := s.sessionStore.SaveRefreshToken(ctx, user.ID, tokenRefreshString); err != nil {
		return AuthResult{}, err
	}

	return AuthResult{
		AccessToken:  tokenAccessString,
		RefreshToken: tokenRefreshString,
	}, nil
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
