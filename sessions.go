package main

import (
	"errors"
	"net/http"
	"database/sql"
	_"github.com/mattn/go-sqlite3"
)

type User struct {
	Id int
	Name string
	Hash string
	Session string
	Csrf string
}

var AuthError = errors.New("Unauthorized")

func getUser(r *http.Request) (User, error) {
	db, err := sql.Open("sqlite3", "users.db")

	var user User

	if err != nil {
		return user, AuthError
	}

	defer db.Close()

	st, err := r.Cookie("session_token")

	if err != nil {
		return user, AuthError
	}

	userCheck := "select id, name, hash, session, csrf from users where session = $1"

	err = db.QueryRow(userCheck, st.Value).Scan(&user.Id, &user.Name, &user.Hash, &user.Session, &user.Csrf)

	if err != nil {
		return user, err
	}

	return user, nil
}

func csrfCheck(r *http.Request, csrfToken string) error {
	db, err := sql.Open("sqlite3", "users.db")

	if err != nil {
		return AuthError
	}

	defer db.Close()

	csrf := r.FormValue("csrf_token")

	if csrf != csrfToken || csrf == "" {
		return AuthError
	}

	return nil
}
