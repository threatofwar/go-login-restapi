package models

import (
	"errors"
	"fmt"
	"go-login-restapi/hash"
	"go-login-restapi/pkg/db"
	"log"
)

type User struct {
	ID       int      `db:"id"`
	Username string   `db:"username"`
	Password string   `db:"password"`
	Emails   []string `db:"-"` // maybe not needed
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

func (u *User) Save() error {
	query := `INSERT INTO users (username, password) VALUES (?, ?)`

	result, err := db.DB.Exec(query, u.Username, u.Password)
	if err != nil {
		return err
	}

	// mostlikely wont encounter this error
	lastInsertID, err := result.LastInsertId()
	if err != nil {
		return errors.New("unable to retrieve last inserted ID")
	}

	u.ID = int(lastInsertID)
	return nil
}

func GetUserWithEmails(username string) (*User, error) {
	var user User
	err := db.DB.Get(&user, "SELECT id, username, password FROM users WHERE username = ?", username)
	if err != nil {
		return nil, err
	}

	// Retrieve the user's emails
	err = db.DB.Select(&user.Emails, "SELECT email FROM emails WHERE user_id = ?", user.ID)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
