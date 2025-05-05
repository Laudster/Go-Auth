package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func createDB() *sql.DB {
	db, err := sql.Open("sqlite3", "users.db")

	if err != nil {
		log.Fatal(err)
	}

	sqlStmt := `
		create table if not exists users (
			id integer not null primary key autoincrement,
			name text,
			email text, 
			hash text,
			session text,
			csrf text
		);
	`

	_, err = db.Exec(sqlStmt)

	if err != nil {
		log.Fatal(err)
	}

	return db
}
