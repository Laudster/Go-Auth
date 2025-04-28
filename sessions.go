package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(r *http.Request) error {
	st, fin := r.Cookie("session_token")

	if fin != nil {
		return AuthError
	}

	username := getUser(st.Value)

	user, ok := users[username]

	if !ok {
		return AuthError
	}

	st, err := r.Cookie("session_token")

	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}

	return nil
}

func csrfCheck(r *http.Request) error {
	st, _ := r.Cookie("session_token")

	username := getUser(st.Value)

	user, ok := users[username]

	if !ok {
		return errors.New("User does not exist")
	}

	csrf := r.FormValue("csrf_token")

	if csrf != user.CSRFToken || csrf == "" {
		return errors.New("Csrf token not correct " + csrf)
	}

	return nil
}
