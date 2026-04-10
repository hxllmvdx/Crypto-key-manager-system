package domain

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
}

func (u *User) SetPassword(plainPassword string) error {
	if len(plainPassword) < 8 {
		return errors.New("Password must be at least 8 characters long")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.PasswordHash = string(hash)
	return nil
}

func (u *User) CheckPassword(plainPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(plainPassword))
	return err
}
