package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	username := r.FormValue("username")

	user, ok := users[username]

	if !ok {
		return errors.New("User does not exist")
	}

	st, err := r.Cookie("session_token")

	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return errors.New("Session token not correct")
	}

	csrf := r.Header.Get("X-CSRF-TOKEN")

	if csrf != user.CSRFToken || csrf == "" {
		return errors.New("Csrf token not correct " + csrf)
	}

	return nil
}