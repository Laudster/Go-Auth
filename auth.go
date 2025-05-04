package main

import (
	"errors"
	"net/http"
	"time"
	_"github.com/mattn/go-sqlite3"
)

func registerate(username string, password string) error {
	if len(password) < 8 || len(username) < 2 {
		return errors.New("Password/Username bad")
	}

	userCheck := "select count(*) from users where name = ?"

	var count int

	err := db.QueryRow(userCheck, username).Scan(&count)

	if err != nil {
		return err
	}

	if count > 0 {
		return errors.New("User already exists")
	}

	hash, _ := hashPassword(password)

	_, err = db.Exec("insert into users(name, hash) values($1, $2)", username, hash)

	if err != nil {
		return err
	}

	return nil
}

func loggingIn(sessionToken string, csrfToken string, username string, password string, w http.ResponseWriter) error {
	userCheck := "select hash from users where name = $1"

	var hash string

	err := db.QueryRow(userCheck, username).Scan(&hash)

	if err != nil || !checkPassword(password, hash) {
		return errors.New("Error logging in")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(168 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(168 * time.Hour),
		HttpOnly: false,
	})

	_, err = db.Exec("update users set session = $1, csrf = $2 where name = $3", sessionToken, csrfToken, username)

	if err != nil {
		return err
	}

	return nil
}

func loggingOut(w http.ResponseWriter, username string) error {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	_, err := db.Exec("update users set session = '', csrf = '' where name = $1", username)

	if err != nil {
		return err
	}

	return nil
}