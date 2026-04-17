package config

import (
	"errors"
	"os"
	"strconv"
)

type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string

	GatewayPort string
	JWTIssuer   string
	JWTSecret   string
	KMSAddr     string
	CryptoAddr  string

	RedisAddr     string
	RedisPassword string
	RedisDB       int
}

func LoadConfig() (*Config, error) {
	port, err := strconv.Atoi(getEnv("DB_PORT", "5432"))
	if err != nil {
		return nil, errors.New("invalid DB_PORT")
	}

	return &Config{
		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     port,
		DBUser:     getEnv("DB_USER", "postgres"),
		DBPassword: getEnv("DB_PASSWORD", "postgres"),
		DBName:     getEnv("DB_NAME", "kms"),

		GatewayPort: getEnv("GATEWAY_PORT", "8080"),
		JWTIssuer:   getEnv("JWT_ISSUER", "kms-gateway"),
		JWTSecret: getEnv("JWT_SECRET", `cLHZ5hULGF6ZTiYpPUKW3b0rs9pD2Yom6cDIE8IbCA6hkmdp4dzOTfKKZYMFTKLy
			jeeEUKeqv1ZRRx2rm4c/cQ==`),
		KMSAddr:    getEnv("KMS_ADDR", "localhost:50051"),
		CryptoAddr: getEnv("CRYPTO_ADDR", "localhost:50052"),
	}, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
