package session

import (
	"context"
	"time"
)

type SessionStore interface {
	SaveRefreshToken(ctx context.Context, userID int64, token string, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, token string) (int64, error)
	DeleteRefreshToken(ctx context.Context, token string) error
}
