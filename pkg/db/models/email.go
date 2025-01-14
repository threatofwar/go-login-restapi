package models

import (
	"database/sql"
)

type Email struct {
	ID                int     `json:"id" db:"id"`
	UserID            int     `json:"user_id" db:"user_id"`
	Email             string  `json:"email" db:"email"`
	Verified          bool    `json:"verified" db:"verified"`
	VerificationToken *string `json:"verification_token" db:"verification_token"`
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
