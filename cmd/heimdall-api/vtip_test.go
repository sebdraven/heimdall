package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
	"github.com/sebdraven/heimdall/internal/vt"
)

// testCSRF is a double-submit token long enough for auth.Manager.Web.
var testCSRF = strings.Repeat("c", 43)

// serveSession sends a request with the session cookie token, "viewer" or
// "analyst", and the CSRF token.
func serveSession(h http.Handler, method, target, token string) (int, string) {
	r := httptest.NewRequest(method, target, nil)
	r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	r.AddCookie(&http.Cookie{Name: auth.CSRFCookie, Value: testCSRF})
	r.Header.Set(auth.CSRFHeader, testCSRF)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// renderAs renders page for the session cookie token.
func renderAs(t *testing.T, s *server, token, page string, data any) string {
	t.Helper()
	s.auth = testAuth()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	s.auth.Web(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, page, http.StatusOK, data)
	})).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("render %s: status %d: %s", page, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// recordingLookup answers at once and records the objects looked up.
type recordingLookup struct {
	mu    sync.Mutex
	asked []string
}

func (l *recordingLookup) DomainResolutions(_ context.Context, domain string) ([]vt.Resolution, error) {
	l.add("d:" + domain)
	return nil, nil
}

func (l *recordingLookup) IPResolutions(_ context.Context, ip string) ([]vt.Resolution, error) {
	l.add("ip:" + ip)
	return nil, nil
}

func (l *recordingLookup) add(object string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked = append(l.asked, object)
}

func (l *recordingLookup) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	asked := l.asked
	l.asked = nil
	return asked
}

func TestEnrichIPJob(t *testing.T) {
	s, l, a := vtJobServer(t)
	h := withTokens(s)
	const ip = "2001:4860:4860::8888"
	running := `{"job":"ip:` + ip + `","state":"running","started_at":"2026-11-04T12:00:00Z"}`

	if code, body := serveSession(h, http.MethodGet, "/rdata/"+ip+"/vt", "viewer"); code != http.StatusOK || body != `{"state":"none"}` {
		t.Errorf("GET before: status %d: %s", code, body)
	}
	if code, _ := serveSession(h, http.MethodPost, "/rdata/"+ip+"/vt?depth=1", "viewer"); code != http.StatusForbidden {
		t.Errorf("session POST as viewer: status %d, want 403", code)
	}
	if code, body := serveAPI(h, http.MethodPost, "/api/vt/enrich/ip/"+ip+"?depth=1", "viewer"); code != http.StatusForbidden || body != `{"error":"forbidden"}` {
		t.Errorf("API POST as viewer: status %d: %s, want 403", code, body)
	}
	if _, ok := s.vtJobs.get(ipTarget(ip)); ok {
		t.Error("POST as viewer started a job")
	}

	// The longhand spelling is the same address.
	if code, body := serveAPI(h, http.MethodPost, "/api/vt/enrich/ip/2001:4860:4860:0:0:0:0:8888?depth=1", "analyst"); code != http.StatusAccepted || body != running {
		t.Errorf("API POST: status %d: %s, want 202 %s", code, body, running)
	}
	// One job per address, whatever the route and the depth.
	if code, body := serveSession(h, http.MethodPost, "/rdata/"+ip+"/vt?depth=2", "analyst"); code != http.StatusAccepted || body != running {
		t.Errorf("session POST: status %d: %s, want 202 %s", code, body, running)
	}
	if code, body := serveSession(h, http.MethodGet, "/rdata/2001:4860:4860:0:0:0:0:8888/vt", "viewer"); code != http.StatusOK || body != running {
		t.Errorf("session GET while running: status %d: %s", code, body)
	}
	if code, body := serveAPI(h, http.MethodGet, "/api/vt/enrich/ip/"+ip, "viewer"); code != http.StatusOK || body != running {
		t.Errorf("API GET while running: status %d: %s", code, body)
	}

	close(l.release)
	waitVTJob(t, s, ipTarget(ip))
	_, viaAPI := serveAPI(h, http.MethodGet, "/api/vt/enrich/ip/"+ip, "viewer")
	if _, viaPage := serveSession(h, http.MethodGet, "/rdata/"+ip+"/vt", "viewer"); viaAPI != viaPage || !strings.Contains(viaAPI, `"state":"done"`) {
		t.Errorf("GET after: %s, rdata route %s", viaAPI, viaPage)
	}
	if n := l.calls.Load(); n != 1 {
		t.Errorf("%d lookups, want 1: one job at depth 1", n)
	}
	want := []string{"vt.enrich ip " + ip + " (looked up 1, cached 0, skipped for budget 0)"}
	if got := a.got(); !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

func TestEnrichIPErrors(t *testing.T) {
	s, _ := graphTestServer(t)
	h := withTokens(s)
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		if code, body := serveSession(h, method, "/rdata/9.9.9.9/vt", "analyst"); code != http.StatusNotFound || body != `{"error":"not found"}` {
			t.Errorf("%s without VirusTotal: status %d: %s, want 404", method, code, body)
		}
	}

	s, _, _ = vtJobServer(t)
	h = withTokens(s)
	for _, tt := range []struct{ method, target string }{
		{http.MethodPost, "/api/vt/enrich/ip/www.x.example?depth=1"},
		{http.MethodGet, "/api/vt/enrich/ip/192.0.2"},
		{http.MethodPost, "/api/vt/enrich/ip/9.9.9.9.9"},
	} {
		if code, body := serveAPI(h, tt.method, tt.target, "analyst"); code != http.StatusBadRequest || body != `{"error":"not an IP address"}` {
			t.Errorf("%s %s: status %d: %s, want 400", tt.method, tt.target, code, body)
		}
	}
	if code, body := serveSession(h, http.MethodPost, "/rdata/www.x.example/vt?depth=1", "analyst"); code != http.StatusBadRequest || body != `{"error":"not an IP address"}` {
		t.Errorf("session POST of a name: status %d: %s, want 400", code, body)
	}
}

func TestEnrichIPDepth(t *testing.T) {
	s, _, a := vtJobServer(t)
	l := &recordingLookup{}
	s.vt.Lookup = l
	f := s.graph.pdnsStore.(*fakeGraphStore)
	h := withTokens(s)
	const ip = "9.9.9.9"
	f.pdns = []ch.PDNSRecord{
		{RRName: "a.example", RRType: "A", RData: ip, LastSeen: t0},
		{RRName: "txt.example", RRType: "TXT", RData: ip, LastSeen: t0},
		{RRName: "cdn-peer.example", RRType: "A", RData: "104.16.0.1", LastSeen: t0},
	}
	f.vt = []ch.VTPair{vtPair("v.example", ip), vtPair("w.example", "104.16.0.1")}

	enrich := func(addr, depth string) []string {
		t.Helper()
		if code, body := serveAPI(h, http.MethodPost, "/api/vt/enrich/ip/"+addr+"?depth="+depth, "analyst"); code != http.StatusAccepted {
			t.Fatalf("POST %s depth %s: status %d: %s", addr, depth, code, body)
		}
		waitVTJob(t, s, ipTarget(addr))
		return l.take()
	}

	if got, want := enrich(ip, "1"), []string{"ip:" + ip}; !slices.Equal(got, want) {
		t.Errorf("depth 1 looked up %v, want %v", got, want)
	}
	if got, want := enrich(ip, "2"), []string{"d:a.example", "d:v.example", "ip:" + ip}; !slices.Equal(got, want) {
		t.Errorf("depth 2 looked up %v, want %v", got, want)
	}
	if got := enrich("104.16.0.1", "2"); len(got) != 0 {
		t.Errorf("depth 2 of a CDN address looked up %v, want nothing", got)
	}
	if _, body := serveAPI(h, http.MethodGet, "/api/vt/enrich/ip/104.16.0.1", "viewer"); !strings.Contains(body, `"skipped_cdn":1`) {
		t.Errorf("CDN job: %s", body)
	}

	f.pdns, f.vt = nil, nil
	for i := range 150 {
		f.pdns = append(f.pdns, ch.PDNSRecord{RRName: fmt.Sprintf("n%03d.example", i), RRType: "A", RData: ip, LastSeen: t0.Add(time.Duration(i) * time.Minute)})
	}
	got := enrich(ip, "2")
	if len(got) != 1+vtIPMaxNames || !slices.Contains(got, "d:n050.example") || slices.Contains(got, "d:n049.example") || !slices.Contains(got, "ip:"+ip) {
		t.Errorf("depth 2 of 150 names: %d lookups, want the address and the %d latest names", len(got), vtIPMaxNames)
	}
	if got := a.got(); len(got) == 0 || got[0] != "vt.enrich ip 9.9.9.9 (looked up 1, cached 0, skipped for budget 0)" {
		t.Errorf("audit = %v", got)
	}
}

func TestLatestNames(t *testing.T) {
	records := []ch.PDNSRecord{
		{RRName: "a.example", RRType: "A", LastSeen: t0},
		{RRName: "b.example", RRType: "AAAA", LastSeen: t0.Add(2 * time.Hour)},
		{RRName: "a.example", RRType: "A", LastSeen: t0.Add(3 * time.Hour)},
		{RRName: "txt.example", RRType: "TXT", LastSeen: t0.Add(5 * time.Hour)},
	}
	pairs := []ch.VTPair{
		{HostName: "c.example", Period: vtPeriod(-time.Hour, 3*time.Hour)},
		{HostName: "b.example", Period: vtPeriod(-time.Hour, 4*time.Hour)},
	}
	if got, want := strings.Join(latestNames(records, pairs, vtIPMaxNames), " "), "b.example a.example c.example"; got != want {
		t.Errorf("names = %s, want %s", got, want)
	}
	if got, want := strings.Join(latestNames(records, pairs, 2), " "), "b.example a.example"; got != want {
		t.Errorf("names capped at 2 = %s, want %s", got, want)
	}
	if got := latestNames(nil, nil, vtIPMaxNames); len(got) != 0 {
		t.Errorf("no record: %v", got)
	}
}

func TestAPIGraphIP(t *testing.T) {
	s, f := graphTestServer(t)
	const ip = "2001:4860:4860::8888"
	f.pdns = []ch.PDNSRecord{
		{RRName: "www.x.example", RRType: "AAAA", RData: ip},
		{RRName: "b.example", RRType: "AAAA", RData: ip},
		{RRName: "txt.example", RRType: "TXT", RData: ip},
	}
	f.vt = []ch.VTPair{vtPair("v.example", ip), vtPair("b.example", ip)}

	code, body := serveGraph(t, s, s.apiGraphIP, "/api/graph/ip/x", "ip", "2001:4860:4860:0:0:0:0:8888")
	want := `{"nodes":[` +
		`{"id":"ip:` + ip + `","kind":"ip","label":"` + ip + `","watched":false,"campaign":"","href":"/rdata/` + ip + `","source":"heimdall"},` +
		`{"id":"d:b.example","kind":"domain","label":"b.example","watched":true,"campaign":"","href":"/domains/b.example","source":"heimdall"},` +
		`{"id":"d:www.x.example","kind":"domain","label":"www.x.example","watched":true,"campaign":"spynote","href":"/domains/www.x.example","source":"heimdall"}],` +
		`"edges":[{"from":"d:b.example","to":"ip:` + ip + `","kind":"AAAA"},` +
		`{"from":"d:www.x.example","to":"ip:` + ip + `","kind":"AAAA"}],` +
		`"truncated":false,"excluded_cdn":0}`
	if code != http.StatusOK || body != want {
		t.Errorf("status %d\n%s\nwant\n%s", code, body, want)
	}
	if _, body := serveGraph(t, s, s.apiGraphIP, "/api/graph/ip/x?vt=1", "ip", ip); body != want {
		t.Errorf("vt=1 without VirusTotal =\n%s\nwant\n%s", body, want)
	}

	s.vt = &vt.Enricher{}
	_, body = serveGraph(t, s, s.apiGraphIP, "/api/graph/ip/x?vt=1", "ip", ip)
	for _, want := range []string{
		`{"id":"d:b.example","kind":"domain","label":"b.example","watched":true,"campaign":"","href":"/domains/b.example","source":"heimdall"}`,
		`{"id":"d:v.example","kind":"domain","label":"v.example","watched":false,"campaign":"","href":"/domains/v.example","source":"vt"}`,
		`{"from":"d:b.example","to":"ip:` + ip + `","kind":"VT","first_seen":"2024-01-02T00:00:00Z","last_seen":"2024-03-04T00:00:00Z"}`,
		`{"from":"d:v.example","to":"ip:` + ip + `","kind":"VT","first_seen":"2024-01-02T00:00:00Z","last_seen":"2024-03-04T00:00:00Z"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("vt graph lacks %s", want)
		}
	}

	if code, body := serveGraph(t, s, s.apiGraphIP, "/api/graph/ip/x", "ip", "www.x.example"); code != http.StatusBadRequest || body != `{"error":"not an IP address"}` {
		t.Errorf("name: status %d: %s, want 400", code, body)
	}
	f.pdns = append(f.pdns, ch.PDNSRecord{RRName: "cdn-peer.example", RRType: "A", RData: "104.16.0.1"})
	if code, body := serveGraph(t, s, s.apiGraphIP, "/api/graph/ip/x?vt=1", "ip", "104.16.0.1"); code != http.StatusOK || body != `{"nodes":[],"edges":[],"truncated":false,"excluded_cdn":1}` {
		t.Errorf("CDN address: status %d: %s", code, body)
	}
}

func TestGraphIPPage(t *testing.T) {
	s, _ := graphTestServer(t)
	code, body := serveGraph(t, s, s.graphIPPage, "/graph/ip/9.9.9.9", "ip", " 9.9.9.9 ")
	for _, want := range []string{
		`<div id="graph" class="graph-canvas" data-source="/graph/ip/9.9.9.9/data"></div>`,
		`<a href="/rdata/9.9.9.9">Back</a>`,
	} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("IP graph page: status %d, lacks %q", code, want)
		}
	}
	if strings.Contains(body, "Depth") || strings.Contains(body, "VirusTotal") {
		t.Error("IP graph page offers depths or VirusTotal without it configured")
	}

	s.vt = &vt.Enricher{Ledger: openLedger{}, Budget: 500}
	_, body = serveGraph(t, s, s.graphIPPage, "/graph/ip/9.9.9.9", "ip", "9.9.9.9")
	for _, want := range []string{
		`id="graph-vt-summary" data-endpoint="/rdata/9.9.9.9/vt?depth=2"`,
		`data-source="/graph/ip/9.9.9.9/data" data-vt="1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("IP graph page with VirusTotal lacks %q", want)
		}
	}

	_, body = serveGraph(t, s, s.graphIPPage, "/graph/ip/104.16.0.1", "ip", "104.16.0.1")
	if !strings.Contains(body, "CDN address (Cloudflare)") || strings.Contains(body, `id="graph"`) || strings.Contains(body, "Enrich with VT") {
		t.Error("CDN address: graph drawn or no CDN notice")
	}
	if code, _ := serveGraph(t, s, s.graphIPPage, "/graph/ip/x", "ip", "www.x.example"); code != http.StatusBadRequest {
		t.Errorf("name: status %d, want 400", code)
	}
}

func TestRenderGraphContainer(t *testing.T) {
	s, _ := graphTestServer(t)
	v := graphView{Title: "9.9.9.9", Back: "/rdata/9.9.9.9", Source: "/graph/ip/9.9.9.9/data", MaxNodes: graphMaxNodes}

	body := renderAs(t, s, "analyst", "graph", v)
	if want := `<div id="graph" class="graph-canvas" data-source="/graph/ip/9.9.9.9/data" data-analyst="1" data-csrf="`; !strings.Contains(body, want) {
		t.Errorf("analyst without VirusTotal: graph page lacks %q", want)
	}
	if strings.Contains(body, "data-vt") {
		t.Error("data-vt set without VirusTotal")
	}

	v.VT = &graphVTView{Endpoint: "/rdata/9.9.9.9/vt?depth=2", Budget: 500, Remaining: 500}
	if body := renderAs(t, s, "analyst", "graph", v); !strings.Contains(body, `data-source="/graph/ip/9.9.9.9/data" data-vt="1" data-analyst="1" data-csrf="`) {
		t.Error("analyst with VirusTotal: graph container lacks data-vt, data-analyst or data-csrf")
	}
	if body := renderAs(t, s, "viewer", "graph", v); strings.Contains(body, "data-analyst") || strings.Contains(body, "data-csrf") {
		t.Error("viewer: graph container offers the enrichment")
	}
}

func TestRenderRdataEnrich(t *testing.T) {
	s := testServer(t)
	v := buildRdataView("9.9.9.9", nil, nil, rdataLimit)
	v.VT = rdataVTView(pg.VTFetch{}, nil, nil)
	v.VT.Endpoint = "/rdata/9.9.9.9/vt"
	const graphLink = `<a class="title-link" href="/graph/ip/9.9.9.9">Graph</a>`

	body := renderAs(t, s, "analyst", "rdata", v)
	for _, want := range []string{
		graphLink,
		`<script src="/static/vtjob.js" defer></script>`,
		`<button type="button" id="vt-enrich" data-csrf="`,
		`<select id="vt-depth"><option value="1">1: the address</option><option value="2">2: and the names seen on it</option></select>`,
		`<p class="notice" id="vt-job" data-endpoint="/rdata/9.9.9.9/vt" hidden></p>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("analyst with VirusTotal: rdata page lacks %q", want)
		}
	}

	// A viewer still follows a running job.
	body = renderAs(t, s, "viewer", "rdata", v)
	if !strings.Contains(body, `id="vt-job"`) || strings.Contains(body, "Enrich with VT") || strings.Contains(body, "vt-depth") {
		t.Error("viewer: rdata page offers the enrichment or does not follow the job")
	}

	v.VT = nil
	body = renderAs(t, s, "analyst", "rdata", v)
	if strings.Contains(body, "Enrich with VT") || strings.Contains(body, "vtjob.js") {
		t.Error("analyst without VirusTotal: rdata page offers the enrichment")
	}
	if !strings.Contains(body, graphLink) {
		t.Error("rdata page of an address lacks the Graph link")
	}

	if body := renderAs(t, s, "analyst", "rdata", buildRdataView("cdn.y.example", nil, nil, rdataLimit)); strings.Contains(body, "/graph/ip/") {
		t.Error("rdata page of a name links to an IP graph")
	}
}
