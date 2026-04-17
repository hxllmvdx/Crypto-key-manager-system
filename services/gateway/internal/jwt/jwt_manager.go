package jwtManager

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

type Claims struct {
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

type TokenManager interface {
	GenerateAccessToken(userID string, timeNow time.Time) (string, error)
	GenerateRefreshToken(userID string, timeNow time.Time) (string, error)
	ParseAccessToken(tokenString string) (*Claims, error)
	ParseRefreshToken(tokenString string) (*Claims, error)
}

type tokenManager struct {
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
	leeway     time.Duration
}

func NewTokenManager(secret, issuer string, accessTTL, refreshTTL, leeway time.Duration) (TokenManager, error) {
	if len(secret) < 32 {
		return nil, jwt.ErrInvalidKey
	}
	if issuer == "" {
		return nil, jwt.ErrInvalidKey
	}
	if accessTTL <= 0 || refreshTTL <= 0 || leeway <= 0 {
		return nil, jwt.ErrInvalidKey
	}

	return &tokenManager{
		secret:     []byte(secret),
		issuer:     issuer,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		leeway:     leeway,
	}, nil
}

func (m *tokenManager) generateToken(userID string, timeNow time.Time, ttl time.Duration, tokenType TokenType) (string, error) {
	if userID == "" {
		return "", jwt.ErrInvalidKey
	}

	claims := &Claims{
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(timeNow.Add(ttl)),
			NotBefore: jwt.NewNumericDate(timeNow),
			IssuedAt:  jwt.NewNumericDate(timeNow),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (m *tokenManager) GenerateAccessToken(userID string, timeNow time.Time) (string, error) {
	return m.generateToken(userID, timeNow, m.accessTTL, TokenTypeAccess)
}

func (m *tokenManager) GenerateRefreshToken(userID string, timeNow time.Time) (string, error) {
	return m.generateToken(userID, timeNow, m.refreshTTL, TokenTypeRefresh)
}

func (m *tokenManager) parseToken(tokenString string, tokenType TokenType) (*Claims, error) {
	claims := &Claims{}

	keyFunc := func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, jwt.ErrSignatureInvalid
		}
		return m.secret, nil
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithLeeway(m.leeway),
	)
	if err != nil || !token.Valid {
		return nil, err
	}

	if claims.TokenType != tokenType {
		return nil, jwt.ErrInvalidKey
	}

	if claims.Subject == "" {
		return nil, jwt.ErrSignatureInvalid
	}

	if claims.ID == "" {
		return nil, jwt.ErrTokenInvalidId
	}

	return claims, nil
}

func (m *tokenManager) ParseAccessToken(tokenString string) (*Claims, error) {
	return m.parseToken(tokenString, TokenTypeAccess)
}

func (m *tokenManager) ParseRefreshToken(tokenString string) (*Claims, error) {
	return m.parseToken(tokenString, TokenTypeRefresh)
}
