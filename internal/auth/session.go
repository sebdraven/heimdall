package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/store/pg"
)

const (
	SessionCookie = "heimdall_session"
	CSRFCookie    = "heimdall_csrf"
	CSRFField     = "csrf_token"
	CSRFHeader    = "X-CSRF-Token"
)

type Store interface {
	SessionUser(ctx context.Context, tokenSHA256 []byte) (pg.User, error)
	TokenUser(ctx context.Context, tokenSHA256 []byte) (pg.User, error)
	CreateSession(ctx context.Context, tokenSHA256 []byte, userID int64, expires time.Time) error
	DeleteSession(ctx context.Context, tokenSHA256 []byte) error
}

type Manager struct {
	store  Store
	ttl    time.Duration
	secure bool
}

func NewManager(store Store, ttl time.Duration, secure bool) *Manager {
	return &Manager{store: store, ttl: ttl, secure: secure}
}

type ctxKey int

const (
	userKey ctxKey = iota
	csrfKey
)

func UserFrom(ctx context.Context) *pg.User {
	u, _ := ctx.Value(userKey).(*pg.User)
	return u
}

func CSRFToken(ctx context.Context) string {
	t, _ := ctx.Value(csrfKey).(string)
	return t
}

func (m *Manager) StartSession(ctx context.Context, w http.ResponseWriter, userID int64) error {
	token, sum, err := NewToken()
	if err != nil {
		return err
	}
	if err := m.store.CreateSession(ctx, sum, userID, time.Now().Add(m.ttl)); err != nil {
		return err
	}
	http.SetCookie(w, m.cookie(SessionCookie, token, m.ttl))
	return m.RotateCSRF(w)
}

func (m *Manager) EndSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		_ = m.store.DeleteSession(r.Context(), HashToken(c.Value))
	}
	http.SetCookie(w, m.cookie(SessionCookie, "", -1))
}

func (m *Manager) RotateCSRF(w http.ResponseWriter) error {
	token, _, err := NewToken()
	if err != nil {
		return err
	}
	http.SetCookie(w, m.cookie(CSRFCookie, token, 0))
	return nil
}

func (m *Manager) cookie(name, value string, maxAge time.Duration) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	}
	switch {
	case maxAge < 0:
		c.MaxAge = -1
	case maxAge > 0:
		c.MaxAge = int(maxAge.Seconds())
	}
	return c
}

// Web resolves the session user, if any, and enforces a double-submit CSRF
// token on unsafe methods.
func (m *Manager) Web(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
			if u, err := m.store.SessionUser(ctx, HashToken(c.Value)); err == nil {
				ctx = context.WithValue(ctx, userKey, &u)
			}
		}

		var csrf string
		if c, err := r.Cookie(CSRFCookie); err == nil && len(c.Value) >= 43 {
			csrf = c.Value
		} else {
			token, _, err := NewToken()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			csrf = token
			http.SetCookie(w, m.cookie(CSRFCookie, csrf, 0))
		}
		if !safeMethod(r.Method) {
			sent := r.Header.Get(CSRFHeader)
			if sent == "" {
				sent = r.PostFormValue(CSRFField)
			}
			if subtle.ConstantTimeCompare([]byte(sent), []byte(csrf)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		ctx = context.WithValue(ctx, csrfKey, csrf)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// API authenticates "Authorization: Bearer <token>".
func (m *Manager) API(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		token = strings.TrimSpace(token)
		if !ok || token == "" {
			unauthorizedAPI(w)
			return
		}
		u, err := m.store.TokenUser(r.Context(), HashToken(token))
		if err != nil {
			unauthorizedAPI(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, &u)))
	})
}

func Require(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFrom(r.Context())
		api := strings.HasPrefix(r.URL.Path, "/api/")
		switch {
		case u == nil && api:
			unauthorizedAPI(w)
		case u == nil && r.Header.Get("HX-Request") == "true":
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
		case u == nil:
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		case !Allowed(u.Role, role) && api:
			writeError(w, http.StatusForbidden, "forbidden")
		case !Allowed(u.Role, role):
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func unauthorizedAPI(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="heimdall"`)
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
