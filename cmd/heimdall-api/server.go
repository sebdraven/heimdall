package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/config"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
	"github.com/sebdraven/heimdall/web"
)

const maxBody = 1 << 20

var pageNames = []string{"login", "error", "campaigns", "campaign", "domain", "rdata", "events", "admin"}

type server struct {
	cfg   *config.Config
	log   *slog.Logger
	pg    *pg.Store
	ch    *ch.Store
	auth  *auth.Manager
	ipLim *auth.Limiter
	usLim *auth.Limiter
	pages map[string]*template.Template
}

func newServer(cfg *config.Config, log *slog.Logger, pgs *pg.Store, chs *ch.Store) (*server, error) {
	funcs := template.FuncMap{
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04:05")
		},
	}
	pages := make(map[string]*template.Template, len(pageNames))
	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcs).ParseFS(web.FS,
			"templates/layout.html", "templates/partials.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", name, err)
		}
		pages[name] = t
	}
	return &server{
		cfg:   cfg,
		log:   log,
		pg:    pgs,
		ch:    chs,
		auth:  auth.NewManager(pgs, cfg.SessionTTL, !cfg.InsecureCookie),
		ipLim: auth.NewLimiter(12*time.Second, 10),
		usLim: auth.NewLimiter(30*time.Second, 5),
		pages: pages,
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	public := func(h http.HandlerFunc) http.Handler { return s.auth.Web(h) }
	page := func(role string, h http.HandlerFunc) http.Handler { return s.auth.Web(auth.Require(role, h)) }
	api := func(role string, h http.HandlerFunc) http.Handler { return s.auth.API(auth.Require(role, h)) }
	const viewer, analyst, admin = auth.RoleViewer, auth.RoleAnalyst, auth.RoleAdmin

	static, _ := fs.Sub(web.FS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", s.healthz)

	mux.Handle("GET /login", public(s.loginPage))
	mux.Handle("POST /login", public(s.login))
	mux.Handle("POST /logout", public(s.logout))

	mux.Handle("GET /{$}", page(viewer, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/campaigns", http.StatusSeeOther)
	}))
	mux.Handle("GET /campaigns", page(viewer, s.campaignsPage))
	mux.Handle("POST /campaigns", page(analyst, s.createCampaign))
	mux.Handle("GET /campaigns/{id}", page(viewer, s.campaignPage))
	mux.Handle("POST /campaigns/{id}/domains", page(analyst, s.addDomains))
	mux.Handle("GET /domains/{fqdn}", page(viewer, s.domainPage))
	mux.Handle("POST /domains/{fqdn}/toggle", page(analyst, s.toggleDomain))
	mux.Handle("DELETE /domains/{fqdn}", page(analyst, s.deleteDomain))
	mux.Handle("GET /rdata/{value...}", page(viewer, s.rdataPage))
	mux.Handle("GET /events", page(viewer, s.eventsPage))
	mux.Handle("GET /admin", page(admin, s.adminPage))
	mux.Handle("POST /admin/resolvers", page(admin, s.createResolver))
	mux.Handle("POST /admin/resolvers/{id}/toggle", page(admin, s.toggleResolver))
	mux.Handle("DELETE /admin/resolvers/{id}", page(admin, s.deleteResolver))
	mux.Handle("POST /admin/nsclasses", page(admin, s.createNSClass))
	mux.Handle("DELETE /admin/nsclasses/{id}", page(admin, s.deleteNSClass))

	mux.Handle("GET /api/pdns/query/{rrname}", api(viewer, s.apiPDNSQuery))
	mux.Handle("GET /api/pdns/rdata/{value...}", api(viewer, s.apiPDNSRdata))
	mux.Handle("GET /api/domains", api(viewer, s.apiDomains))
	mux.Handle("POST /api/domains", api(analyst, s.apiCreateDomain))
	mux.Handle("PATCH /api/domains/{fqdn}", api(analyst, s.apiPatchDomain))
	mux.Handle("DELETE /api/domains/{fqdn}", api(analyst, s.apiDeleteDomain))
	mux.Handle("GET /api/campaigns", api(viewer, s.apiCampaigns))
	mux.Handle("POST /api/campaigns", api(analyst, s.apiCreateCampaign))
	mux.Handle("GET /api/events", api(viewer, s.apiEvents))
	mux.Handle("GET /api/pivots/{fqdn}", api(viewer, s.apiPivots))

	return s.middleware(mux)
}

func (s *server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic", "err", v, "path", r.URL.Path)
				http.Error(rec, "internal error", http.StatusInternalServerError)
			}
			s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(), "remote", clientIP(r))
		}()
		next.ServeHTTP(rec, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	res := map[string]string{"postgres": "ok", "clickhouse": "ok"}
	status := http.StatusOK
	if err := s.pg.Ping(ctx); err != nil {
		res["postgres"], status = "down", http.StatusServiceUnavailable
		s.log.Warn("healthz", "postgres", err)
	}
	if err := s.ch.Ping(ctx); err != nil {
		res["clickhouse"], status = "down", http.StatusServiceUnavailable
		s.log.Warn("healthz", "clickhouse", err)
	}
	writeJSON(w, status, res)
}

func (s *server) housekeeping(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.pg.PurgeSessions(ctx); err != nil {
				s.log.Warn("purge sessions", "err", err)
			} else if n > 0 {
				s.log.Info("purged sessions", "count", n)
			}
			s.ipLim.Sweep()
			s.usLim.Sweep()
		}
	}
}

func (s *server) audit(r *http.Request, action, target string) {
	var uid *int64
	if u := auth.UserFrom(r.Context()); u != nil {
		uid = &u.ID
	}
	if err := s.pg.Audit(r.Context(), uid, action, target); err != nil {
		s.log.Error("audit", "action", action, "target", target, "err", err)
	}
}

type view struct {
	User *pg.User
	CSRF string
	Data any
}

func (v view) Can(role string) bool {
	return v.User != nil && auth.Allowed(v.User.Role, role)
}

func (s *server) render(w http.ResponseWriter, r *http.Request, page string, status int, data any) {
	s.execute(w, r, page, "layout", status, data)
}

func (s *server) execute(w http.ResponseWriter, r *http.Request, page, name string, status int, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	v := view{User: auth.UserFrom(r.Context()), CSRF: auth.CSRFToken(r.Context()), Data: data}
	var buf bytes.Buffer
	var err error
	if name == "layout" {
		err = t.ExecuteTemplate(&buf, name, v)
	} else {
		err = t.ExecuteTemplate(&buf, name, data)
	}
	if err != nil {
		s.log.Error("render", "page", page, "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *server) fail(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	if err != nil {
		s.log.Error(msg, "err", err, "path", r.URL.Path)
	}
	if status >= 500 {
		msg = "Internal error."
	}
	s.render(w, r, "error", status, map[string]any{"Status": status, "Message": msg, "Back": backPath(r, "/")})
}

func (s *server) storeFail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pg.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "Not found.", nil)
	case errors.Is(err, pg.ErrConflict):
		s.fail(w, r, http.StatusConflict, "Already exists.", nil)
	case errors.Is(err, pg.ErrInvalid):
		s.fail(w, r, http.StatusBadRequest, "Invalid value.", nil)
	default:
		s.fail(w, r, http.StatusInternalServerError, "store error", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// backPath returns the same-origin path of the Referer, or fallback.
func backPath(r *http.Request, fallback string) string {
	u, err := url.Parse(r.Referer())
	if err != nil || u.Path == "" || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return fallback
	}
	if u.Host != "" && u.Host != r.Host {
		return fallback
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// parseTime accepts a relative duration ("24h"), a date, RFC 3339 or epoch
// seconds.
func parseTime(v string, now time.Time) (time.Time, error) {
	v = strings.TrimSpace(v)
	if d, err := time.ParseDuration(v); err == nil {
		return now.Add(-d), nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q", v)
}

func intParam(r *http.Request, name string, def, maxV int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, maxV)
}
