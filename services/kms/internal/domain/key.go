package domain

import "time"

type Key struct {
	ID           string `gorm:"primary_key;size:36"`
	Version      uint32
	Algorithm    string
	EncryptedKey []byte
	CreatedAt    time.Time
}
