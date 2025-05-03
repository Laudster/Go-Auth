package main

import (
	"database/sql"
	"log"
	_"github.com/mattn/go-sqlite3"
)

func createDB() {
	db, err := sql.Open("sqlite3", "users.db")

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	sqlStmt := `
		create table if not exists users (
			id integer not null primary key autoincrement,
			name text,
			hash text,
			session text,
			csrf text
		);
	`

	_, err = db.Exec(sqlStmt)

	if err != nil {
		log.Fatal(err)
	}
}