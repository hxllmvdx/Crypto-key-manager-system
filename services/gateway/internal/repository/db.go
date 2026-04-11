package repository

import (
	"fmt"

	"github.com/hxllmvdx/Crypto-key-management-system/pkg/domain"
	"github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disabled",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&domain.User{}); err != nil {
		return nil, err
	}

	return db, nil
}
