package db

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// DB is the global variable that holds the database connection
var DB *sqlx.DB

// InitDB initializes the database connection
func InitDB() {
	var err error
	DB, err = sqlx.Connect("sqlite3", "./user.db")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Database connected successfully!")
}
