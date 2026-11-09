package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
	"github.com/sebdraven/heimdall/internal/vt"
)

// fakeTokens maps the SHA-256 of a token to its user.
type fakeTokens map[string]pg.User

func (f fakeTokens) TokenUser(_ context.Context, sum []byte) (pg.User, error) {
	u, ok := f[string(sum)]
	if !ok {
		return pg.User{}, pg.ErrNotFound
	}
	return u, nil
}

// SessionUser takes the tokens as session cookies too.
func (f fakeTokens) SessionUser(ctx context.Context, sum []byte) (pg.User, error) {
	return f.TokenUser(ctx, sum)
}

func (fakeTokens) CreateSession(context.Context, []byte, int64, time.Time) error { return nil }

func (fakeTokens) DeleteSession(context.Context, []byte) error { return nil }

// testAuth accepts the tokens "viewer" and "analyst", as bearer tokens or
// session cookies.
func testAuth() *auth.Manager {
	return auth.NewManager(fakeTokens{
		string(auth.HashToken("viewer")):  {ID: 1, Username: "val", Role: auth.RoleViewer},
		string(auth.HashToken("analyst")): {ID: 2, Username: "ana", Role: auth.RoleAnalyst},
	}, time.Hour, false)
}

func withTokens(s *server) http.Handler {
	s.auth = testAuth()
	return s.routes()
}

func serveAPI(h http.Handler, method, target, token string) (int, string) {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// usedLedger has counted n lookups today.
type usedLedger struct {
	openLedger
	n int
}

func (l usedLedger) VTUsageToday(context.Context) (int, error) { return l.n, nil }

func TestAPIVTDisabled(t *testing.T) {
	s, _ := graphTestServer(t)
	h := withTokens(s)
	for _, tt := range []struct{ method, target string }{
		{http.MethodGet, "/api/vt/ip/192.0.2.1"},
		{http.MethodGet, "/api/vt/budget"},
		{http.MethodPost, "/api/vt/enrich/domain/www.x.example?depth=1"},
		{http.MethodGet, "/api/vt/enrich/domain/www.x.example"},
		{http.MethodPost, "/api/vt/enrich/campaign/7"},
		{http.MethodGet, "/api/vt/enrich/campaign/7"},
		{http.MethodPost, "/api/vt/enrich/ip/9.9.9.9?depth=1"},
		{http.MethodGet, "/api/vt/enrich/ip/9.9.9.9"},
	} {
		if code, body := serveAPI(h, tt.method, tt.target, "analyst"); code != http.StatusNotFound || body != `{"error":"not found"}` {
			t.Errorf("%s %s without VirusTotal: status %d: %s, want 404", tt.method, tt.target, code, body)
		}
	}
}

func TestAPIVTEnrichDomain(t *testing.T) {
	s, l, _ := vtJobServer(t)
	h := withTokens(s)
	const path = "/api/vt/enrich/domain/www.x.example"
	running := `{"job":"domain:www.x.example","state":"running","started_at":"2026-11-04T12:00:00Z"}`

	if code, body := serveAPI(h, http.MethodGet, path, "viewer"); code != http.StatusOK || body != `{"state":"none"}` {
		t.Errorf("GET before: status %d: %s", code, body)
	}
	if code, body := serveAPI(h, http.MethodPost, path+"?depth=1", "viewer"); code != http.StatusForbidden || body != `{"error":"forbidden"}` {
		t.Errorf("POST as viewer: status %d: %s, want 403", code, body)
	}
	if _, ok := s.vtJobs.get(domainTarget("www.x.example")); ok {
		t.Error("POST as viewer started a job")
	}
	if code, body := serveAPI(h, http.MethodPost, path+"?depth=1", "analyst"); code != http.StatusAccepted || body != running {
		t.Errorf("POST: status %d: %s, want 202 %s", code, body, running)
	}
	// The graph route shares the job of the target and starts none.
	if code, body := serveVT(context.Background(), s.enrichGraphDomain, http.MethodPost); code != http.StatusAccepted || body != running {
		t.Errorf("POST on the graph route: status %d: %s, want 202 %s", code, body, running)
	}
	if code, body := serveAPI(h, http.MethodGet, path, "viewer"); code != http.StatusOK || body != running {
		t.Errorf("GET while running: status %d: %s", code, body)
	}

	close(l.release)
	waitVTJob(t, s, domainTarget("www.x.example"))
	_, viaAPI := serveAPI(h, http.MethodGet, path, "viewer")
	if _, viaGraph := serveVT(context.Background(), s.vtJobDomain, http.MethodGet); viaAPI != viaGraph || !strings.Contains(viaAPI, `"state":"done"`) {
		t.Errorf("GET after: %s, graph route %s", viaAPI, viaGraph)
	}
	if n := l.calls.Load(); n != 2 {
		t.Errorf("%d lookups, want 2: one job", n)
	}
}

func TestAPIVTEnrichCampaign(t *testing.T) {
	s, l, _ := vtJobServer(t)
	h := withTokens(s)
	running := `{"job":"campaign:7","state":"running","started_at":"2026-11-04T12:00:00Z"}`

	if code, body := serveAPI(h, http.MethodPost, "/api/vt/enrich/campaign/7", "analyst"); code != http.StatusAccepted || body != running {
		t.Errorf("POST: status %d: %s, want 202 %s", code, body, running)
	}
	if _, body := serveGraph(t, s, s.vtJobCampaign, "/graph/campaign/7/vt", "id", "7"); body != running {
		t.Errorf("graph route: %s, want %s", body, running)
	}
	if code, body := serveAPI(h, http.MethodGet, "/api/vt/enrich/campaign/7", "viewer"); code != http.StatusOK || body != running {
		t.Errorf("GET: status %d: %s", code, body)
	}
	if code, _ := serveAPI(h, http.MethodPost, "/api/vt/enrich/campaign/8", "analyst"); code != http.StatusNotFound {
		t.Errorf("unknown campaign: status %d, want 404", code)
	}
	if code, _ := serveAPI(h, http.MethodPost, "/api/vt/enrich/campaign/7", "viewer"); code != http.StatusForbidden {
		t.Errorf("POST as viewer: status %d, want 403", code)
	}
	close(l.release)
	waitVTJob(t, s, campaignTarget(7))
}

func TestAPIVTIPInvalid(t *testing.T) {
	s, _ := graphTestServer(t)
	s.vt = &vt.Enricher{}
	for _, v := range []string{"www.x.example", "192.0.2", "192.0.2.1.5", ""} {
		if code, body := serveGraph(t, s, s.apiVTIP, "/api/vt/ip/x", "ip", v); code != http.StatusBadRequest || body != `{"error":"not an IP address"}` {
			t.Errorf("%q: status %d: %s, want 400", v, code, body)
		}
	}
}

func TestVTIPJSON(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	const ip = "198.51.100.7"

	if got, want := encode(t, toVTIPJSON(ip, rdataVTView(pg.VTFetch{}, nil, nil))),
		`{"ip":"198.51.100.7","looked_up_at":null,"status":null,"names":[]}`; got != want {
		t.Errorf("never looked up = %s, want %s", got, want)
	}
	if got, want := encode(t, toVTIPJSON(ip, rdataVTView(pg.VTFetch{FetchedAt: t0.In(cet), Status: "empty"}, nil, nil))),
		`{"ip":"198.51.100.7","looked_up_at":"2026-03-01T12:00:00Z","status":"empty","names":[]}`; got != want {
		t.Errorf("empty cache = %s, want %s", got, want)
	}

	v := rdataVTView(pg.VTFetch{FetchedAt: t0.In(cet), Status: "ok", Count: 2}, []ch.VTPair{
		{HostName: "z.example", IP: ip, Period: vtPeriod(-48*time.Hour, -time.Hour)},
		{HostName: "a.example", IP: ip, Period: vtPeriod(-72*time.Hour, -2*time.Hour)},
	}, map[string]pg.Domain{"a.example": {FQDN: "a.example", Campaign: "spynote"}})
	want := `{"ip":"198.51.100.7","looked_up_at":"2026-03-01T12:00:00Z","status":"ok","names":[` +
		`{"host_name":"z.example","first_seen":"2026-02-27T12:00:00Z","last_seen":"2026-03-01T11:00:00Z","watched":false,"campaign":""},` +
		`{"host_name":"a.example","first_seen":"2026-02-26T12:00:00Z","last_seen":"2026-03-01T10:00:00Z","watched":true,"campaign":"spynote"}]}`
	if got := encode(t, toVTIPJSON(ip, v)); got != want {
		t.Errorf("names =\n%s\nwant\n%s", got, want)
	}
}

func TestAPIVTBudget(t *testing.T) {
	s, _ := graphTestServer(t)
	h := withTokens(s)
	for used, want := range map[int]string{
		0:   `{"budget":500,"used_today":0,"remaining":500}`,
		120: `{"budget":500,"used_today":120,"remaining":380}`,
		500: `{"budget":500,"used_today":500,"remaining":0}`,
	} {
		s.vt = &vt.Enricher{Ledger: usedLedger{n: used}, Budget: 500}
		if code, body := serveAPI(h, http.MethodGet, "/api/vt/budget", "viewer"); code != http.StatusOK || body != want {
			t.Errorf("used %d: status %d: %s, want %s", used, code, body, want)
		}
	}
}
