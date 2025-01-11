package models

import (
	"database/sql"
	"fmt"
	"go-login-restapi/pkg/db"
	"log"
)

type Email struct {
	ID                int     `json:"id" db:"id"`
	UserID            int     `json:"user_id" db:"user_id"`
	Email             string  `json:"email" db:"email"`
	Verified          bool    `json:"verified" db:"verified"`
	VerificationToken *string `json:"verification_token" db:"verification_token"`
}

func FindEmailByAddress(email string) (Email, error) {
	var emailRecord Email
	err := db.DB.Get(&emailRecord, "SELECT user_id FROM emails WHERE email = ?", email)
	return emailRecord, err
}

// UpdateEmailVerificationStatus updates the verification status of the email
func UpdateEmailVerificationStatus(email string) error {
	_, err := db.DB.Exec(`
		UPDATE emails
		SET verified = TRUE
		WHERE email = $1
	`, email)
	if err != nil {
		return fmt.Errorf("failed to update email verification status: %w", err)
	}
	return nil
}

func StoreVerificationToken(email string, verificationToken string) error {
	_, err := db.DB.Exec(`
		UPDATE emails 
		SET verification_token = ? 
		WHERE email = ?`, verificationToken, email)
	if err != nil {
		log.Println("Error storing verification token:", err)
		return err
	}
	return nil
}

func GetEmailByToken(verificationToken, email string) (*Email, error) {
	var emailRecord Email
	err := db.DB.Get(&emailRecord, `SELECT id, user_id, email, verified, verification_token FROM emails WHERE verification_token = ? AND email = ?`, verificationToken, email)
	if err != nil {
		log.Println("Error retrieving email by token:", err)
		return nil, err
	}
	return &emailRecord, nil
}

func (e *Email) Save(tx *sql.Tx) error {
	query := `INSERT INTO emails (user_id, email) VALUES (?, ?)`

	_, err := tx.Exec(query, e.UserID, e.Email)
	return err
}

func (e *Email) Update(tx *sql.Tx) error {
	query := `UPDATE emails SET verification_token = ? WHERE email = ?`
	_, err := tx.Exec(query, e.VerificationToken, e.Email)
	return err
}
