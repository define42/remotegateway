package main

import (
	"context"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

type sessionData struct {
	User       *User
	Namespaces []string
	CreatedAt  time.Time
}

const sessionKey = "session"

var sessionManager = newSessionManager()

func init() {
	gob.Register(sessionData{})
}

const sessionTTL = 30 * time.Minute

func newSessionManager() *scs.SessionManager {
	manager := scs.New()
	manager.Store = memstore.New()
	manager.Lifetime = sessionTTL
	manager.Cookie.Name = "cv_session"
	manager.Cookie.Path = "/"
	manager.Cookie.HttpOnly = true
	manager.Cookie.SameSite = http.SameSiteLaxMode
	manager.Cookie.Secure = true
	return manager
}

func createSession(ctx context.Context, u *User) error {
	if err := sessionManager.RenewToken(ctx); err != nil {
		return err
	}
	sessionManager.Put(ctx, sessionKey, sessionData{
		User:      u,
		CreatedAt: time.Now(),
	})
	return nil
}

func getSession(r *http.Request) (sessionData, bool) {
	sess, ok := sessionManager.Get(r.Context(), sessionKey).(sessionData)
	if !ok || sess.User == nil {
		return sessionData{}, false
	}
	return sess, true
}

func destroySession(ctx context.Context) error {
	return sessionManager.Destroy(ctx)
}

type sessionContextKey struct{}

func sessionMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		req, w := humachi.Unwrap(ctx)

		sess, ok := getSession(req)
		if !ok || sess.User == nil {
			http.Redirect(w, req, "/login", http.StatusSeeOther)
			return
		}

		next(huma.WithValue(ctx, sessionContextKey{}, sess))
	}
}
