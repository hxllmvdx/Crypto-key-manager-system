package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrTokenNotFound = errors.New("Refresh token not found")

func key(token string) string {
	return fmt.Sprintf("refresh_token:%s", token)
}

type store struct {
	redisDB *redis.Client
	timeout time.Duration
}

func NewStore(addr string, timeout time.Duration) (SessionStore, error) {
	if timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &store{
		redisDB: rdb,
		timeout: timeout,
	}, nil
}

func (s *store) Close() error {
	return s.redisDB.Close()
}

func (s *store) SaveRefreshToken(ctx context.Context, userID string, token string) error {
	if token == "" || userID == "" {
		return errors.New("userID or token is empty")
	}

	return s.redisDB.Set(ctx, key(token), userID, s.timeout).Err()
}

func (s *store) GetRefreshToken(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errors.New("token is empty")
	}

	val, err := s.redisDB.Get(ctx, key(token)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("failed to save token: %w", err)
	}

	return val, nil
}

func (s *store) DeleteRefreshToken(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("token is empty")
	}

	return s.redisDB.Del(ctx, key(token)).Err()
}
