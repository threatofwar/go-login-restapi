package models

import (
	"fmt"
	"go-login-restapi/pkg/db"
)

// UpdateEmailVerificationStatus updates the verification status of the email
func UpdateEmailVerificationStatus(email string) error {
	// Update the email verification status in the database
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
