package main

import (
	jwtManager "github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/jwt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/client"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/config"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/middleware"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/repository"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/routes"
	"google.golang.org/grpc"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("cfg init: %v", err)
	}

	db, err := repository.NewDB(cfg)
	if err != nil {
		log.Fatalf("db init: %v", err)
	}

	cryptoConn, err := grpc.NewClient(cfg.CryptoAddr)
	if err != nil {
		log.Fatalf("crypto client init: %v", err)
	}
	defer func(cryptoConn *grpc.ClientConn) {
		err := cryptoConn.Close()
		if err != nil {
			log.Fatalf("crypto client init: %v", err)
		}
	}(cryptoConn)

	cryptoClient := client.NewCryptoClient(cryptoConn, 10)

	router := gin.Default()

	authGroup := router.Group("/auth")
	routes.AuthRoutes(authGroup)

	apiGroup := router.Group("/api")

	tokenManager, err := jwtManager.NewTokenManager(cfg.JWTSecret, cfg.JWTIssuer, 15*time.Minute, 24*time.Hour, 5*time.Second)
	if err != nil {
		log.Fatalf("token manager init: %v", err)
	}

	apiGroup.Use(middleware.AuthMiddleware(tokenManager))
	routes.ApiRoutes(apiGroup)
}
