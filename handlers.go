package main

import (
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"remotegateway/internal/config"
	"remotegateway/internal/ldap"
	"remotegateway/internal/session"
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

func handleLoginPost(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok, err := extractCredentials(r)
		if err != nil {
			serveLogin(w, "Invalid form submission.")
			return
		}
		if !ok {
			serveLogin(w, "Missing credentials.")
			return
		}

		user, err := ldap.LdapAuthenticateAccess(username, password, settings)
		if err != nil {
			log.Printf("ldap auth failed for %s: %v", username, err)
			serveLogin(w, "Invalid credentials.")
			return
		}

		if err := sessionManager.CreateSession(r.Context(), user); err != nil {
			log.Printf("session create failed for %s: %v", username, err)
			serveLogin(w, "Login failed.")
			return
		}
		http.Redirect(w, r, "/api/dashboard", http.StatusSeeOther)
	}
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

func handleLogout(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := sessionManager.DestroySession(r.Context()); err != nil {
			log.Printf("session destroy failed: %v", err)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func handleKdcProxy(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	log.Printf(
		"KdcProxy request: method=%s remote=%s ua=%q content_type=%q content_len=%d",
		r.Method,
		r.RemoteAddr,
		r.UserAgent(),
		r.Header.Get("Content-Type"),
		r.ContentLength,
	)
	w.Header().Set("Content-Type", "application/kerberos")
	w.WriteHeader(http.StatusOK)
}
