package models

import (
	"go-login-restapi/pkg/db"
	"log"
)

// Email represents the emails table
// type Email struct {
// 	ID                     int     `json:"id" db:"id"`
// 	UserID                 int     `json:"user_id" db:"user_id"`
// 	Email                  string  `json:"email" db:"email"`
// 	Verified               bool    `json:"verified" db:"verified"`
// 	VerificationToken      *string `json:"verification_token" db:"verification_token"`
// 	PasswordResetTokenUsed bool    `json:"password_reset_token_used" db:"password_reset_token_used"`
// }

// Save saves a new email to the emails table
func (e *Email) Save() error {
	query := `INSERT INTO emails (user_id, email) VALUES (?, ?)`
	_, err := db.DB.Exec(query, e.UserID, e.Email)
	if err != nil {
		log.Println("Error saving email:", err)
		return err
	}
	return nil
}
