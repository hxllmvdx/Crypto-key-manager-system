package session

import (
	"context"
)

type SessionStore interface {
	SaveRefreshToken(ctx context.Context, userID string, token string) error
	GetRefreshToken(ctx context.Context, token string) (string, error)
	DeleteRefreshToken(ctx context.Context, token string) error
}
