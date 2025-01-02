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
	log.Println("Database connected successfully!")
}
