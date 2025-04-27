package main

import (
	"html/template"
	"fmt"
	"net/http"
	"time"
)

// https://www.youtube.com/watch?v=OmLdoEMcr_Y&t=74s

type Login struct {
	HashedPassword string
	SessionToken string
	CSRFToken string
}

var users = map[string]Login{}

var templates = template.Must(template.ParseFiles("index.html"))

func register(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 8 || len(username) < 8 {
		http.Error(w, "Invalid username/password", http.StatusNotAcceptable)
		return
	}

	if _, ok := users[username]; ok {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,

	}

	fmt.Fprintf(w, "User registered successfully")
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]

	if !ok || !checkPassword(password, user.HashedPassword) {
		http.Error(w, "Invalid username/password", http.StatusUnauthorized)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: sessionToken,
		Expires: time.Now().Add(168 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token",
		Value: csrfToken,
		Expires:  time.Now().Add(168 * time.Hour),
		HttpOnly: false,
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken

	users[username] = user

	fmt.Fprintf(w, "User logged in successfully")
}

func logout(w http.ResponseWriter, r *http.Request) {
	if err := Authorize(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	username := r.FormValue("username")
	user, _ := users[username]

	user.SessionToken = ""
	user.CSRFToken = ""
	
	users[username] = user

	fmt.Fprintf(w, "User logged out")
}

func protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := Authorize(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")

	fmt.Fprintf(w, "Welcome %s", username)
}

func mainPage(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "index.html", "ignore")

	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}
}

func main(){
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	//http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.HandleFunc("/", mainPage)

	http.ListenAndServe(":8080", nil)
}
