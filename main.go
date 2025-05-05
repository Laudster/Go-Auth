package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
)

// https://www.youtube.com/watch?v=OmLdoEMcr_Y&t=74s

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

var db *sql.DB

var templates = template.Must(template.ParseFiles("index.html"))

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	err := registerate(username, password, email)

	if err != nil {
		redirectURL := fmt.Sprintf("/?error=%s", url.QueryEscape(err.Error()))
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	err = loggingIn(sessionToken, csrfToken, username, password, w)

	if err != nil {
		redirectURL := fmt.Sprintf("/?error=%s", url.QueryEscape(err.Error()))
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	err := loggingIn(sessionToken, csrfToken, username, password, w)

	if err != nil {
		redirectURL := fmt.Sprintf("/?error=%s", url.QueryEscape(err.Error()))
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	user, err := getUser(r)

	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := csrfCheck(r, user.Csrf); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = loggingOut(w, user.Name)

	if err != nil {
		http.Error(w, "Error logging out "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func mainPage(w http.ResponseWriter, r *http.Request) {
	user, _ := getUser(r)

	errorMessage := r.URL.Query().Get("error")

	pageData := []string{user.Name, errorMessage}

	err := templates.ExecuteTemplate(w, "index.html", pageData)

	if err != nil {
		http.Error(w, "Could not load template", http.StatusInternalServerError)
		return
	}
}

func main() {
	db = createDB()

	defer db.Close()

	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/", mainPage)

	http.ListenAndServe(":8080", nil)
}
