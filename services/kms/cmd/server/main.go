package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	kmsv1 "github.com/hxllmvdx/Crypto-key-management-system/services/kms/gen/kms/v1"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/config"
	handler "github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/handler"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/repository"
	"github.com/hxllmvdx/Crypto-key-management-system/services/kms/internal/service"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.Load()

	db, err := repository.NewDB(cfg)
	if err != nil {
		log.Fatalf("db init: %v", err)
	}
	fmt.Println("db initialized")

	keyRepo := repository.NewKeyRepository(db)
	keyService := service.NewKeyService(keyRepo)

	grpcServer := grpc.NewServer()
	kmsv1.RegisterKMSServiceServer(grpcServer, handler.NewKMSServer(keyService))

	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Println("gRPC server listening on " + cfg.GRPCPort)

	ticker := time.NewTicker(time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Println("check for rotation")
				if _, err := keyService.RotateEnabledKeysThatExpired(context.Background(), time.Now()); err != nil {
					log.Fatalf("rotateExpiredKeys: %v", err)
				}
			}
		}
	}()

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
