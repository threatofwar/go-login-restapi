package db

import (
	"log"
)

func CreateTables() {
	CreateUserTable()
	CreateEmailsTable()
	log.Println("All tables have been created or already exist.")
}

func CreateUserTable() {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("User table created or already exists.")
}

func CreateEmailsTable() {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS emails (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		email TEXT NOT NULL UNIQUE,
		verified BOOLEAN DEFAULT FALSE,
		verification_token TEXT,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Emails table created or already exists.")
}
