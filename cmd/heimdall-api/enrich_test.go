package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/enrich"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

type fakeEnrichStore struct {
	mu        sync.Mutex
	resolvers []pg.Resolver
	saved     map[string]enrich.Result
}

func (f *fakeEnrichStore) Resolvers(context.Context) ([]pg.Resolver, error) { return f.resolvers, nil }

func (f *fakeEnrichStore) SaveDomainEnrich(_ context.Context, r enrich.Result) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved[r.FQDN] = r
	return nil
}

func (f *fakeEnrichStore) DomainEnrich(_ context.Context, fqdn string) (enrich.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.saved[fqdn]
	if !ok {
		return enrich.Result{}, pg.ErrNotFound
	}
	return r, nil
}

// stubDNS answers an A record for www.x.example, nothing otherwise.
type stubDNS struct{}

func (stubDNS) Resolve(_ context.Context, server, fqdn, qtype string) resolver.Observation {
	o := resolver.Observation{Domain: fqdn, QType: qtype, Resolver: server, Rcode: "NOERROR", Rdata: []string{}}
	if fqdn == "www.x.example" && qtype == "A" {
		o.Rdata, o.TTL = []string{"192.0.2.1"}, 60
	}
	return o
}

type stubRegistry struct{}

func (stubRegistry) Lookup(context.Context, string) (*enrich.RDAP, error) {
	return nil, errors.New("rdap x.example: HTTP 404")
}

// stubCT answers once release is closed.
type stubCT struct{ release chan struct{} }

func (c stubCT) Lookup(ctx context.Context, zone string) (*enrich.CT, error) {
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &enrich.CT{Zone: zone, Total: 1, Certificates: []enrich.Certificate{{ID: "42", Names: []string{"*.x.example"}, Sources: []string{"certspotter", "onyphe"}}},
		Names: []string{"*.x.example", "api.x.example"}}, nil
}

type stubPDNS struct{}

func (stubPDNS) SubdomainsOf(context.Context, string, int) ([]enrich.Subdomain, error) {
	return []enrich.Subdomain{{Name: "www.x.example"}, {Name: "mail.x.example"}}, nil
}

func enrichTestServer(t *testing.T) (*server, *fakeEnrichStore, chan struct{}, *fakeAudit) {
	t.Helper()
	s, _ := graphTestServer(t)
	store := &fakeEnrichStore{
		resolvers: []pg.Resolver{{Address: "1.1.1.1:53"}, {Address: "9.9.9.9:53", Enabled: true}},
		saved:     map[string]enrich.Result{},
	}
	release := make(chan struct{})
	s.enrich = &enrich.Enricher{
		DNS: stubDNS{}, RDAP: stubRegistry{}, CT: stubCT{release}, PDNS: stubPDNS{},
		Now: func() time.Time { return vtJobTime },
	}
	s.enrichDB = store
	s.enrichJobs.now = func() time.Time { return vtJobTime }
	a := &fakeAudit{}
	s.audits = a
	return s, store, release, a
}

func waitEnrichJob(t *testing.T, s *server, fqdn string) {
	t.Helper()
	cur, ok := s.enrichJobs.get(domainTarget(fqdn))
	if !ok {
		t.Fatalf("no enrichment of %s", fqdn)
	}
	select {
	case <-cur.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("enrichment of %s still running", fqdn)
	}
}

func TestEnrichDomainJob(t *testing.T) {
	s, store, release, a := enrichTestServer(t)
	h := withTokens(s)
	const job = "/api/enrich/domain/www.x.example"
	running := `{"job":"domain:www.x.example","state":"running","started_at":"2026-11-04T12:00:00Z"}`

	if code, body := serveAPI(h, http.MethodGet, job, "viewer"); code != http.StatusOK || body != `{"state":"none"}` {
		t.Errorf("GET before: status %d: %s", code, body)
	}
	if code, body := serveAPI(h, http.MethodGet, "/api/domains/www.x.example/enrich", "viewer"); code != http.StatusNotFound || body != `{"error":"not found"}` {
		t.Errorf("data before: status %d: %s, want 404", code, body)
	}
	if code, body := serveAPI(h, http.MethodPost, job, "viewer"); code != http.StatusForbidden || body != `{"error":"forbidden"}` {
		t.Errorf("POST as viewer: status %d: %s, want 403", code, body)
	}
	if code, _ := serveSession(h, http.MethodPost, "/domains/www.x.example/enrich", "viewer"); code != http.StatusForbidden {
		t.Errorf("page POST as viewer: status %d, want 403", code)
	}
	if _, ok := s.enrichJobs.get(domainTarget("www.x.example")); ok {
		t.Error("a viewer started an enrichment")
	}

	if code, body := serveAPI(h, http.MethodPost, "/api/enrich/domain/WWW.X.example.", "analyst"); code != http.StatusAccepted || body != running {
		t.Errorf("POST: status %d: %s, want 202 %s", code, body, running)
	}
	if code, body := serveSession(h, http.MethodPost, "/domains/www.x.example/enrich", "analyst"); code != http.StatusAccepted || body != running {
		t.Errorf("page POST while running: status %d: %s, want the same job", code, body)
	}
	if code, body := serveSession(h, http.MethodGet, "/domains/www.x.example/enrich", "viewer"); code != http.StatusOK || body != running {
		t.Errorf("page GET while running: status %d: %s", code, body)
	}

	close(release)
	waitEnrichJob(t, s, "www.x.example")
	summary := "partial: dns 1, rdap failed, ct 1, subdomains 2, lookyloo not configured"
	done := `{"job":"domain:www.x.example","state":"done","started_at":"2026-11-04T12:00:00Z","finished_at":"2026-11-04T12:00:00Z",` +
		`"status":"partial","counts":{"dns":1,"rdap":0,"ct":1,"subdomains":2,"lookyloo":0},` +
		`"errors":{"lookyloo":"lookyloo not configured","rdap":"rdap x.example: HTTP 404"},"summary":"` + summary + `"}`
	if _, body := serveAPI(h, http.MethodGet, job, "viewer"); body != done {
		t.Errorf("GET after:\n%s\nwant\n%s", body, done)
	}
	if got := a.got(); len(got) != 1 || got[0] != "domain.enrich www.x.example ("+summary+")" {
		t.Errorf("audit = %v", got)
	}
	saved, _ := store.DomainEnrich(context.Background(), "www.x.example")
	if saved.Status != enrich.StatusPartial || saved.DNS == nil || saved.DNS.Resolver != "9.9.9.9:53" || saved.CT.Zone != "x.example" {
		t.Errorf("saved %+v, want the enabled resolver and CT below x.example", saved)
	}

	code, body := serveAPI(h, http.MethodGet, "/api/domains/www.x.example/enrich", "viewer")
	if code != http.StatusOK {
		t.Fatalf("data: status %d: %s", code, body)
	}
	var got struct {
		FQDN      string            `json:"fqdn"`
		FetchedAt time.Time         `json:"fetched_at"`
		Status    string            `json:"status"`
		RDAP      *enrich.RDAP      `json:"rdap"`
		Errors    map[string]string `json:"errors"`
		Graph     graphJSON         `json:"graph"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.FQDN != "www.x.example" || !got.FetchedAt.Equal(vtJobTime) || got.Status != "partial" || got.RDAP != nil || got.Errors["rdap"] == "" {
		t.Errorf("data = %s", body)
	}
	for _, key := range []string{
		`"dns":{"resolver":"9.9.9.9:53","records":[{"qtype":"A","rcode":"NOERROR","ttl":60,"rdata":["192.0.2.1"]}`, `"zone":null`, `"rdap":null`,
		`"names":["*.x.example"],"sources":["certspotter","onyphe"]}`, `"lookyloo":null`,
	} {
		if !strings.Contains(body, key) {
			t.Errorf("data lacks %s", key)
		}
	}
	nodes, edges := graphSummary(got.Graph)
	if want := "d:www.x.example ip:192.0.2.1 d:mail.x.example d:x.example d:api.x.example"; nodes != want {
		t.Errorf("graph nodes = %s\nwant          %s", nodes, want)
	}
	if want := "d:www.x.example>ip:192.0.2.1/A d:www.x.example>d:mail.x.example/SUB d:www.x.example>d:x.example/CERT d:www.x.example>d:api.x.example/CERT"; edges != want {
		t.Errorf("graph edges = %s\nwant          %s", edges, want)
	}
	if n := got.Graph.Nodes[0]; !n.Watched || n.Campaign != "spynote" {
		t.Errorf("root node %+v, want watched in spynote", n)
	}
	_, page := serveSession(h, http.MethodGet, "/domains/www.x.example/enrich/data", "viewer")
	if page != body {
		t.Errorf("page data differs from the API:\n%s\n%s", page, body)
	}
}

func TestEnrichInvalidFQDN(t *testing.T) {
	s, _, release, _ := enrichTestServer(t)
	close(release)
	h := withTokens(s)
	for _, tt := range []struct{ method, target string }{
		{http.MethodPost, "/api/enrich/domain/localhost"},
		{http.MethodGet, "/api/enrich/domain/localhost"},
		{http.MethodGet, "/api/domains/bad%20name.example/enrich"},
	} {
		if code, body := serveAPI(h, tt.method, tt.target, "analyst"); code != http.StatusBadRequest || body != `{"error":"invalid fqdn"}` {
			t.Errorf("%s %s: status %d: %s, want 400", tt.method, tt.target, code, body)
		}
	}
	if code, body := serveSession(h, http.MethodPost, "/domains/localhost/enrich", "analyst"); code != http.StatusBadRequest || body != `{"error":"invalid fqdn"}` {
		t.Errorf("page POST: status %d: %s, want 400", code, body)
	}
}

func TestEnrichNoResolver(t *testing.T) {
	s, store, release, _ := enrichTestServer(t)
	store.resolvers = []pg.Resolver{{Address: "9.9.9.9:53"}}
	close(release)
	if code, _ := serveVT(context.Background(), s.enrichDomain, http.MethodPost); code != http.StatusAccepted {
		t.Fatalf("POST: status %d", code)
	}
	waitEnrichJob(t, s, "www.x.example")
	saved, _ := store.DomainEnrich(context.Background(), "www.x.example")
	if saved.DNS != nil || saved.Errors[enrich.SourceDNS] != "no active resolver" || saved.CT == nil || saved.Subdomains == nil {
		t.Errorf("saved %+v, want DNS failed and the other sources kept", saved)
	}
}

func TestEnrichGraph(t *testing.T) {
	res := enrich.Result{
		FQDN: "www.x.example",
		DNS: &enrich.DNS{Records: []enrich.Record{
			{QType: "A", Rdata: []string{"192.0.2.1", "104.16.0.1"}},
			{QType: "AAAA", Rdata: []string{"2606:4700::1"}},
			{QType: "CNAME", Rdata: []string{"CDN.Y.example."}},
			{QType: "MX", Rdata: []string{"10 mail.x.example", "0 ."}},
			{QType: "TXT", Rdata: []string{`"v=spf1 -all"`}},
		}},
		Zone:       &enrich.Zone{Name: "x.example", NS: []string{"ns2.p.example", "ns1.p.example"}},
		Subdomains: &enrich.Subdomains{Names: []enrich.Subdomain{{Name: "www.x.example"}, {Name: "api.x.example"}}},
		CT:         &enrich.CT{Names: []string{"*.x.example", "api.x.example", "www.x.example", "admin@x.example"}},
	}
	g := enrichGraph(res, testCDN(), graphMaxNodes)
	nodes, edges := graphSummary(g)
	if want := "d:www.x.example ip:192.0.2.1 d:cdn.y.example d:mail.x.example " + testNSSet + " d:api.x.example d:x.example"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:www.x.example>ip:192.0.2.1/A d:www.x.example>d:cdn.y.example/CNAME d:www.x.example>d:mail.x.example/MX " +
		"d:www.x.example>" + testNSSet + "/NS_SET d:www.x.example>d:api.x.example/SUB d:www.x.example>d:x.example/CERT " +
		"d:www.x.example>d:api.x.example/CERT"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	if g.ExcludedCDN != 2 || g.Truncated {
		t.Errorf("excluded_cdn %d truncated %v, want 2 and false", g.ExcludedCDN, g.Truncated)
	}

	capped := enrichGraph(res, testCDN(), 3)
	if nodes, _ := graphSummary(capped); nodes != "d:www.x.example ip:192.0.2.1 d:cdn.y.example" || !capped.Truncated {
		t.Errorf("capped: nodes %q truncated %v", nodes, capped.Truncated)
	}

	res.Zone.NS = []string{"ns1.p.example"}
	if _, edges := graphSummary(enrichGraph(res, testCDN(), graphMaxNodes)); strings.Contains(edges, "NS_SET") {
		t.Error("a single nameserver makes an NS set node")
	}
	if g := enrichGraph(enrich.Result{FQDN: "x.example", Status: enrich.StatusError}, testCDN(), graphMaxNodes); len(g.Nodes) != 1 || len(g.Edges) != 0 {
		t.Errorf("failed enrichment: %+v, want the name alone", g)
	}
}

func TestEnrichGraphLookyloo(t *testing.T) {
	res := enrich.Result{
		FQDN: "jjspy.com",
		CT:   &enrich.CT{Names: []string{"www.jjspy.com"}},
		Lookyloo: &enrich.Lookyloo{
			Captures: []enrich.Capture{
				{UUID: "a", URL: "https://jjspy.com/", FinalURL: "https://www.jjspy.com/", Redirects: []string{"https://www.jjspy.com/"}},
				{UUID: "b", URL: "https://jjspy.com/", FinalURL: "https://jjspy.com/"},
				{UUID: "c", URL: "http://jjspy.com/", FinalURL: "https://LANDING.example./x", Redirects: []string{"https://landing.example/x"}},
				{UUID: "d", URL: "https://jjspy.com/", FinalURL: "http://192.0.2.7/", Redirects: []string{"http://192.0.2.7/"}},
				{UUID: "e", URL: "https://other.example/", FinalURL: "https://elsewhere.example/", Redirects: []string{"https://elsewhere.example/"}},
			},
			Trackers: []enrich.TrackerSeen{{Kind: "gads", ID: "AW-11021906314", Captures: 2}, {Kind: "ua", ID: "UA-132944514-1", Captures: 1}},
		},
	}
	nodes, edges := graphSummary(enrichGraph(res, testCDN(), graphMaxNodes))
	if want := "d:jjspy.com d:www.jjspy.com d:landing.example ip:192.0.2.7 t:gads:AW-11021906314 t:ua:UA-132944514-1"; nodes != want {
		t.Errorf("nodes = %s\nwant    %s", nodes, want)
	}
	if want := "d:jjspy.com>d:www.jjspy.com/CERT d:jjspy.com>d:www.jjspy.com/REDIRECT d:jjspy.com>d:landing.example/REDIRECT d:jjspy.com>ip:192.0.2.7/REDIRECT " +
		"d:jjspy.com>t:gads:AW-11021906314/TRACKER d:jjspy.com>t:ua:UA-132944514-1/TRACKER"; edges != want {
		t.Errorf("edges = %s\nwant    %s", edges, want)
	}
	if n := enrichGraph(res, testCDN(), graphMaxNodes).Nodes[4]; n.Kind != nodeTracker || n.Label != "gads AW-11021906314" || n.Href != "" {
		t.Errorf("tracker node %+v", n)
	}
}

func TestSummarize(t *testing.T) {
	sum := summarize(enrich.Result{
		Status:     enrich.StatusOK,
		DNS:        &enrich.DNS{Records: []enrich.Record{{Rdata: []string{"a", "b"}}, {Rdata: []string{}}, {Rdata: []string{"c"}}}},
		RDAP:       &enrich.RDAP{},
		CT:         &enrich.CT{Total: 700, Certificates: make([]enrich.Certificate, 500)},
		Subdomains: &enrich.Subdomains{Names: make([]enrich.Subdomain, 4)},
		Lookyloo:   &enrich.Lookyloo{CapturesFound: 12, CapturesRead: 10},
	})
	if sum.Counts != (enrichCounts{DNS: 3, RDAP: 1, CT: 700, Subdomains: 4, Lookyloo: 10}) || sum.Summary != "ok: dns 3, rdap 1, ct 700, subdomains 4, lookyloo 10" || sum.Errors != nil {
		t.Errorf("summary %+v", sum)
	}

	for _, tt := range []struct {
		desc string
		r    enrich.Result
		want string
	}{
		{"no capture", enrich.Result{Status: enrich.StatusOK, Lookyloo: &enrich.Lookyloo{Captures: []enrich.Capture{}}},
			"ok: dns 0, rdap 0, ct 0, subdomains 0, lookyloo: no capture"},
		{"not configured", enrich.Result{Status: enrich.StatusOK, Errors: map[string]string{enrich.SourceLookyloo: "lookyloo not configured"}},
			"ok: dns 0, rdap 0, ct 0, subdomains 0, lookyloo not configured"},
		{"failed", enrich.Result{Status: enrich.StatusPartial, Lookyloo: &enrich.Lookyloo{CapturesRead: 2},
			Errors: map[string]string{enrich.SourceLookyloo: "lookyloo urls: HTTP 404"}},
			"partial: dns 0, rdap 0, ct 0, subdomains 0, lookyloo failed"},
	} {
		if got := summarize(tt.r).Summary; got != tt.want {
			t.Errorf("%s: %q, want %q", tt.desc, got, tt.want)
		}
	}
}

func TestRenderDomainLookyloo(t *testing.T) {
	s := testServer(t)
	at := time.Date(2026, 11, 13, 6, 30, 20, 390000000, time.UTC)
	old := time.Date(2026, 6, 1, 6, 0, 0, 0, time.UTC)
	submitted := "c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e04"
	res := &enrich.Result{
		FQDN: "jjspy.com", FetchedAt: vtJobTime, Status: enrich.StatusOK,
		Lookyloo: &enrich.Lookyloo{
			Instance: "http://citizen-lab.tail399dd.ts.net:5100", CapturesFound: 12, CapturesRead: 2, Truncated: true, Submitted: &submitted,
			Captures: []enrich.Capture{
				{UUID: "0b6e7a52-6f0d-4a39-9d0c-3c1b1f6f8a01", Time: at, URL: "https://jjspy.com/", Title: "JJSpy", FinalURL: "https://www.jjspy.com/",
					Redirects: []string{"https://www.jjspy.com/"}},
				{UUID: "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c03", Time: old, URL: "https://jjspy.com/", FinalURL: "https://jjspy.com/", Redirects: []string{}},
			},
			Trackers: []enrich.TrackerSeen{
				{Kind: "gads", ID: "AW-11021906314", FirstSeen: at, LastSeen: at, Captures: 1},
				{Kind: "payment", ID: "stripe:pk_live_51HxYzAbCdEf0123456789abcdefghijklmnopqrstuvwxyz", FirstSeen: old, LastSeen: at, Captures: 2},
			},
		},
	}
	body := renderAs(t, s, "viewer", "domain", map[string]any{
		"FQDN": "jjspy.com", "Sharing": map[string]uint64{}, "Enrich": &enrichView{Endpoint: "/domains/jjspy.com/enrich", Result: res},
	})
	for _, want := range []string{
		"<h3>Lookyloo</h3>",
		`2 of 12 captures on <a href="http://citizen-lab.tail399dd.ts.net:5100">http://citizen-lab.tail399dd.ts.net:5100</a>, the latest read`,
		`submitted <a href="http://citizen-lab.tail399dd.ts.net:5100/tree/` + submitted + `"><code>` + submitted + `</code></a>`,
		"an absence proves nothing",
		`<td><a href="http://citizen-lab.tail399dd.ts.net:5100/tree/0b6e7a52-6f0d-4a39-9d0c-3c1b1f6f8a01">JJSpy</a></td>`,
		`<td><code>https://jjspy.com/</code><br>→ <code>https://www.jjspy.com/</code></td>`,
		`<td><code>https://www.jjspy.com/</code><br></td>`,
		`<td><a href="http://citizen-lab.tail399dd.ts.net:5100/tree/9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c03">9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c03</a></td>`,
		`<td><code>https://jjspy.com/</code></td>`, "<td>—</td>",
		"<th>Kind</th><th>ID</th><th>First (UTC)</th><th>Last (UTC)</th><th>Captures</th>",
		"<td>gads</td>\n      <td><code>AW-11021906314</code></td>",
		"<td><code>stripe:pk_live_51HxYzAbCdEf0123456789abcdefghijklmnopqrstuvwxyz</code></td>",
		"2026-06-01 06:00:00", "2026-11-13 06:30:20",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("domain page lacks %q", want)
		}
	}

	res.Lookyloo = &enrich.Lookyloo{Instance: "http://lookyloo.example", Captures: []enrich.Capture{}, Trackers: []enrich.TrackerSeen{}}
	body = renderAs(t, s, "viewer", "domain", map[string]any{
		"FQDN": "jjspy.com", "Sharing": map[string]uint64{}, "Enrich": &enrichView{Endpoint: "/domains/jjspy.com/enrich", Result: res},
	})
	if !strings.Contains(body, "No capture of this name.") || strings.Contains(body, "<th>Kind</th>") || strings.Contains(body, "submitted") {
		t.Error("no capture: wrong Lookyloo section")
	}
}

const certSHA = "6f1a0e4b5c3d2e1f00112233445566778899aabbccddeeff0123456789abcdef"

func TestRenderDomainEnrich(t *testing.T) {
	s := testServer(t)
	seven := int64(7)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	res := &enrich.Result{
		FQDN: "www.x.example", FetchedAt: vtJobTime, Status: enrich.StatusPartial,
		DNS:  &enrich.DNS{Resolver: "9.9.9.9:53", Records: []enrich.Record{{QType: "A", Rcode: "NOERROR", TTL: 60, Rdata: []string{"192.0.2.1"}}}},
		Zone: &enrich.Zone{Name: "x.example", SOA: []string{"ns1.p.example h.x.example 1 2 3 4 5"}, NS: []string{"ns1.p.example"}},
		CT: &enrich.CT{Zone: "x.example", Total: 2, Names: []string{"*.x.example", "old.x.example"},
			Certificates: []enrich.Certificate{
				{ID: "42", CertSHA256: certSHA, Issuer: "Let's Encrypt", NotBefore: at, NotAfter: at.AddDate(0, 3, 0), Revoked: true, Names: []string{"*.x.example"}, Sources: []string{"certspotter", "onyphe"}},
				{ID: "7", Issuer: "C=US, O=Let's Encrypt, CN=R3", NotBefore: at, NotAfter: at, Names: []string{"old.x.example"}},
			}},
		Subdomains: &enrich.Subdomains{Zone: "x.example", Names: []enrich.Subdomain{{Name: "api.x.example", FirstSeen: at, LastSeen: at}}},
		Errors:     map[string]string{enrich.SourceRDAP: "rdap x.example: HTTP 404"},
	}
	data := func(r *enrich.Result) map[string]any {
		return map[string]any{
			"FQDN": "www.x.example", "Domain": &pg.Domain{FQDN: "www.x.example", CampaignID: &seven, Campaign: "spynote"},
			"Sharing": map[string]uint64{}, "Enrich": &enrichView{Endpoint: "/domains/www.x.example/enrich", Result: r},
			"Campaigns": []campaignRef{{ID: 8, Name: "other"}, {ID: 7, Name: "spynote"}}, "CurrentCampaign": seven,
		}
	}

	body := renderAs(t, s, "analyst", "domain", data(res))
	for _, want := range []string{
		"<h2>Enrichment</h2>", "last enriched 2026-11-04 12:00:00 (partial) · resolver 9.9.9.9:53",
		`<button type="button" id="enrich-start" data-csrf="`,
		`<button type="button" id="link-open" data-fqdn="www.x.example">Link to campaign</button>`,
		`<p class="notice" id="enrich-job" data-endpoint="/domains/www.x.example/enrich" data-label="Enrichment" hidden></p>`,
		`<script src="/static/vtjob.js" defer></script>`, `<script src="/static/link.js" defer></script>`,
		`<li class="error">rdap: rdap x.example: HTTP 404</li>`,
		`<a href="/rdata/192.0.2.1"><code>192.0.2.1</code></a>`,
		`<h3>Zone <a href="/domains/x.example">x.example</a></h3>`, "<td>SOA</td><td><code>ns1.p.example h.x.example 1 2 3 4 5</code></td>",
		"<h3>Certificate Transparency</h3>", "<th>Names</th><th>Sources</th>",
		"<code>*.x.example</code><br></td>\n      <td>certspotter, onyphe</td>",
		"<code>old.x.example</code><br></td>\n      <td>—</td>",
		"<td><code>" + certSHA + "</code></td>", `<td><span class="error">revoked</span></td>`,
		"<td>—</td>\n      <td>C=US, O=Let&#39;s Encrypt, CN=R3</td>", "<td>no</td>",
		"2026-01-01 00:00:00 → 2026-04-01 00:00:00", "<code>*.x.example</code>",
		`<td><a href="/domains/api.x.example">api.x.example</a></td>`,
		`<dialog id="link-campaign" data-csrf="`,
		`<input type="radio" name="link-choice" value="current" data-campaign="7"> Current campaign: spynote`,
		`<option value="8">other</option><option value="7">spynote</option>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("analyst: domain page lacks %q", want)
		}
	}
	if strings.Contains(body, "<h3>RDAP") {
		t.Error("failed RDAP shown")
	}
	if strings.Contains(body, "crt.sh") {
		t.Error("domain page links to crt.sh")
	}

	body = renderAs(t, s, "viewer", "domain", data(res))
	if !strings.Contains(body, `id="enrich-job"`) || !strings.Contains(body, "vtjob.js") {
		t.Error("viewer: domain page does not follow the enrichment")
	}
	for _, unwanted := range []string{"enrich-start", "link-open", "link-campaign", "link.js"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("viewer: domain page has %s", unwanted)
		}
	}

	d := data(nil)
	d["CurrentCampaign"] = int64(0)
	body = renderAs(t, s, "analyst", "domain", d)
	if !strings.Contains(body, "not enriched yet") || strings.Contains(body, "<h3>") || strings.Contains(body, `value="current"`) {
		t.Error("not enriched, no campaign: wrong section or current campaign offered")
	}
}
