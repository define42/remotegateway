package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
)

func extractCredentials(r *http.Request) (string, string, bool, error) {
	username, password, ok := r.BasicAuth()
	if ok && username != "" && password != "" {
		return username, password, true, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", false, err
	}
	username = strings.TrimSpace(r.FormValue("username"))
	password = r.FormValue("password")
	if username == "" || password == "" {
		return username, password, false, nil
	}
	return username, password, true, nil
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username, password, ok, err := extractCredentials(r)
	if err != nil {
		serveLogin(w, "Invalid form submission.")
		return
	}
	if !ok {
		serveLogin(w, "Missing credentials.")
		return
	}

	user, err := ldapAuthenticateAccess(username, password)
	if err != nil {
		log.Printf("ldap auth failed for %s: %v", username, err)
		serveLogin(w, "Invalid credentials.")
		return
	}

	if err := createSession(r.Context(), user); err != nil {
		log.Printf("session create failed for %s: %v", username, err)
		serveLogin(w, "Login failed.")
		return
	}
	http.Redirect(w, r, "/api/dashboard", http.StatusSeeOther)
}

func serveLogin(w http.ResponseWriter, message string) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if message != "" {
		errorHTML = `<div class="error">` + html.EscapeString(message) + `</div>`
	}
	fmt.Fprint(w, strings.Replace(loginHTML, "{{ERROR}}", errorHTML, 1))
}

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}

func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	serveLogin(w, "")
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := destroySession(r.Context()); err != nil {
		log.Printf("session destroy failed: %v", err)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
