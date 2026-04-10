package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
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

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				fmt.Println("gRPC server stopped by context done")
				return
			case <-ticker.C:
				fmt.Println("check for rotation")

				opCtx, cancel := context.WithTimeout(ctx, time.Second*10)
				defer cancel()

				if err := keyService.RotateEnabledKeysThatExpired(opCtx, time.Now()); err != nil {
					log.Printf("rotateExpiredKeys: %v", err)
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				fmt.Println("gRPC server stopped by context done")
				return
			case <-ticker.C:
				fmt.Println("check for deletion")

				opCtx, cancel := context.WithTimeout(ctx, time.Second*10)
				defer cancel()

				if err := keyService.DestroyOldDisabledKeys(opCtx, time.Now()); err != nil {
					log.Printf("destroyOldDisabledKeys: %v", err)
				}
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-quit

	fmt.Println("start shutdown")
	grpcServer.GracefulStop()

	stop()

	wg.Wait()

	fmt.Println("successful shutdown")
}
