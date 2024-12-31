package models

import (
	"go-login-restapi/pkg/db"
	"log"
)

// Email represents the emails table
type Email struct {
	ID     int    `json:"id"`
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
}

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
