package main

import (
	"html/template"
	"fmt"
	"net/http"
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

	fmt.Println(w, "User registered successfully")
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
	//http.HandleFunc("/login", login)
	//http.HandleFunc("/logout", logout)
	//http.HandleFunc("/protected", protected)
	http.HandleFunc("/", mainPage)

	http.ListenAndServe(":80", nil)
}
