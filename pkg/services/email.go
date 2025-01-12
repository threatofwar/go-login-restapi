package services

import (
	"fmt"
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"
	"log"
)

func FindEmailByAddress(email string) (models.Email, error) {
	var emailRecord models.Email
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

func GetEmailByToken(verificationToken, email string) (*models.Email, error) {
	var emailRecord models.Email
	err := db.DB.Get(&emailRecord, `SELECT id, user_id, email, verified, verification_token FROM emails WHERE verification_token = ? AND email = ?`, verificationToken, email)
	if err != nil {
		log.Println("Error retrieving email by token:", err)
		return nil, err
	}
	return &emailRecord, nil
}
