package db

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

var DB *sqlx.DB

func InitDB() {
	var err error
	DB, err = sqlx.Connect("sqlite3", "./user.db")
	if err != nil {
		log.Fatal(err)
	}
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
}

func CreateEmailsTable() {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS emails (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		email TEXT NOT NULL UNIQUE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	)`)
	if err != nil {
		log.Fatal(err)
	}
}
