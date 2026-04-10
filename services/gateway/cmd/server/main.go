package main

import (
	"log"

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
	defer cryptoConn.Close()

	cryptoClient := client.NewCryptoClient(cryptoConn, 10)

	router := gin.Default()

	authGroup := router.Group("/auth")
	routes.AuthRoutes(authGroup)

	apiGroup := router.Group("/api")
	apiGroup.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	routes.ApiRoutes(apiGroup)
}
