package models

import (
	"database/sql"
	"errors"
	"fmt"
	"go-login-restapi/hash"
	"go-login-restapi/pkg/db"
	"log"
)

type User struct {
	ID                     int     `db:"id"`
	Username               string  `db:"username"`
	Password               string  `db:"password"`
	PasswordResetToken     *string `db:"password_reset_token"`
	PasswordResetTokenUsed bool    `db:"password_reset_token_used"`
	Emails                 []Email `db:"-"` // maybe not needed
}

func FindUserByID(userID int) (User, error) {
	var user User
	err := db.DB.Get(&user, "SELECT id, username, password FROM users WHERE id = ?", userID)
	return user, err
}

func StorePasswordResetToken(userID int, resetToken string) error {
	_, err := db.DB.Exec("UPDATE users SET password_reset_token = ?, password_reset_token_used = FALSE WHERE id = ?", resetToken, userID)
	return err
}

func InsertTestUser() {
	var count int
	err := db.DB.Get(&count, "SELECT COUNT(*) FROM users WHERE username = ?", "user")
	if err != nil {
		log.Fatalf("Error checking for existing user: %v", err)
	}

	if count == 0 {
		hashedPassword := hash.HashPassword("123")
		_, err := db.DB.Exec(`INSERT INTO users (username, password) VALUES (?, ?)`, "user", hashedPassword)
		if err != nil {
			log.Fatalf("Error inserting test user: %v", err)
		}
		fmt.Println("Test user inserted")
	} else {
		fmt.Println("Test user already exists")
	}
}

func InsertTestUserEmail() {
	var userID int
	err := db.DB.Get(&userID, "SELECT id FROM users WHERE username = ?", "user")
	if err != nil {
		log.Fatalf("Error fetching user ID: %v", err)
	}

	emails := []string{"user@user", "user@email"}
	for _, email := range emails {
		// Check if the email already exists
		var count int
		err := db.DB.Get(&count, "SELECT COUNT(*) FROM emails WHERE email = ?", email)
		if err != nil {
			log.Fatalf("Error checking email existence: %v", err)
		}

		// If the email doesn't exist, insert it
		if count == 0 {
			_, err := db.DB.Exec(`INSERT INTO emails (user_id, email) VALUES (?, ?)`, userID, email)
			if err != nil {
				log.Fatalf("Error inserting email for user: %v", err)
			}
			fmt.Printf("Email %s inserted for user\n", email)
		} else {
			fmt.Printf("Email %s already exists\n", email)
		}
	}
}

func (u *User) Save(tx *sql.Tx) error {
	query := `INSERT INTO users (username, password) VALUES (?, ?)`

	result, err := tx.Exec(query, u.Username, u.Password)
	if err != nil {
		return err
	}

	lastInsertID, err := result.LastInsertId()
	if err != nil {
		return errors.New("unable to retrieve last inserted ID")
	}

	u.ID = int(lastInsertID)
	return nil
}

func GetUser(username string, withEmails bool) (*User, error) {
	var user User
	err := db.DB.Get(&user, "SELECT id, username, password, password_reset_token, password_reset_token_used FROM users WHERE username = ?", username)
	if err != nil {
		return nil, err
	}

	if withEmails {
		var emails []Email
		err = db.DB.Select(&emails, "SELECT id, user_id, email, verified, verification_token FROM emails WHERE user_id = ?", user.ID)
		if err != nil {
			return nil, err
		}
		user.Emails = emails
	}

	return &user, nil
}
