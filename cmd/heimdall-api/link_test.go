package main

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sebdraven/heimdall/internal/auth"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

// fakeLinkStore holds the campaigns 7 "spynote" and 8 "other" and the
// watched name in.x.example, in 7.
type fakeLinkStore struct {
	mu        sync.Mutex
	campaigns map[int64]pg.Campaign
	domains   map[string]pg.Domain
	imports   []string
	updates   []string
}

func newFakeLinkStore() *fakeLinkStore {
	seven := int64(7)
	return &fakeLinkStore{
		campaigns: map[int64]pg.Campaign{7: {ID: 7, Name: "spynote"}, 8: {ID: 8, Name: "other"}},
		domains:   map[string]pg.Domain{"in.x.example": {FQDN: "in.x.example", CampaignID: &seven, Campaign: "spynote"}},
	}
}

func (f *fakeLinkStore) Campaigns(context.Context) ([]pg.Campaign, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.SortedFunc(maps.Values(f.campaigns), func(a, b pg.Campaign) int { return cmp.Compare(a.Name, b.Name) }), nil
}

func (f *fakeLinkStore) Campaign(_ context.Context, id int64) (pg.Campaign, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.campaigns[id]
	if !ok {
		return pg.Campaign{}, pg.ErrNotFound
	}
	return c, nil
}

func (f *fakeLinkStore) CreateCampaign(_ context.Context, name, family, description string) (pg.Campaign, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.campaigns {
		if c.Name == name {
			return pg.Campaign{}, fmt.Errorf("%w (campaigns_name_key)", pg.ErrConflict)
		}
	}
	c := pg.Campaign{ID: int64(len(f.campaigns) + 10), Name: name, Family: family, Description: description}
	f.campaigns[c.ID] = c
	return c, nil
}

func (f *fakeLinkStore) Domain(_ context.Context, fqdn string) (pg.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.domains[fqdn]
	if !ok {
		return pg.Domain{}, pg.ErrNotFound
	}
	return d, nil
}

func (f *fakeLinkStore) ImportDomains(_ context.Context, fqdns []string, campaignID *int64, interval int, source string, addedBy *int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, fqdn := range fqdns {
		if _, ok := f.domains[fqdn]; ok {
			continue
		}
		f.domains[fqdn] = pg.Domain{FQDN: fqdn, CampaignID: campaignID, IntervalSeconds: interval, Source: source, AddedBy: addedBy}
		f.imports = append(f.imports, fmt.Sprintf("%s campaign %d every %ds from %s by %d", fqdn, *campaignID, interval, source, *addedBy))
		n++
	}
	return n, nil
}

func (f *fakeLinkStore) UpdateDomain(_ context.Context, fqdn string, p pg.DomainPatch) (pg.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.domains[fqdn]
	if !ok {
		return pg.Domain{}, pg.ErrNotFound
	}
	if p.SetCampaign {
		d.CampaignID = p.CampaignID
		f.updates = append(f.updates, fmt.Sprintf("%s campaign %d", fqdn, *p.CampaignID))
	}
	f.domains[fqdn] = d
	return d, nil
}

func linkTestServer(t *testing.T) (http.Handler, *fakeLinkStore, *fakeAudit) {
	t.Helper()
	s, _ := graphTestServer(t)
	f := newFakeLinkStore()
	a := &fakeAudit{}
	s.links, s.audits = f, a
	return withTokens(s), f, a
}

// postLink posts body under the bearer token, or with session the session
// cookie and, with csrf, the CSRF token.
func postLink(h http.Handler, target, token, body string, session, csrf bool) (int, string) {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if session {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
		r.AddCookie(&http.Cookie{Name: auth.CSRFCookie, Value: testCSRF})
		if csrf {
			r.Header.Set(auth.CSRFHeader, testCSRF)
		}
	} else {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func TestLinkBadRequests(t *testing.T) {
	h, f, a := linkTestServer(t)
	for _, tt := range []struct{ target, body, want string }{
		{"/api/domains/new.x.example/link", `{}`, "campaign or new_campaign"},
		{"/api/domains/new.x.example/link", `{"campaign": 7, "new_campaign": {"name": "x"}}`, "campaign or new_campaign"},
		{"/api/domains/new.x.example/link", `{"campaign": null}`, "campaign or new_campaign"},
		{"/api/domains/new.x.example/link", `not json`, "invalid JSON body"},
		{"/api/domains/new.x.example/link", `{"campaign": 7, "family": "x"}`, "invalid JSON body"},
		{"/api/domains/new.x.example/link", `{"new_campaign": {"name": "  "}}`, "name is required"},
		{"/api/domains/localhost/link", `{"campaign": 7}`, "invalid fqdn"},
	} {
		if code, body := postLink(h, tt.target, "analyst", tt.body, false, false); code != http.StatusBadRequest || body != `{"error":"`+tt.want+`"}` {
			t.Errorf("%s: status %d: %s, want 400 %s", tt.body, code, body, tt.want)
		}
	}
	if code, body := postLink(h, "/api/domains/new.x.example/link", "analyst", `{"campaign": 99}`, false, false); code != http.StatusNotFound || body != `{"error":"unknown campaign"}` {
		t.Errorf("unknown campaign: status %d: %s, want 404", code, body)
	}
	if code, body := postLink(h, "/api/domains/new.x.example/link", "analyst", `{"new_campaign": {"name": "spynote"}}`, false, false); code != http.StatusConflict || body != `{"error":"campaign exists"}` {
		t.Errorf("taken name: status %d: %s, want 409", code, body)
	}
	if code, body := postLink(h, "/api/domains/new.x.example/link", "viewer", `{"campaign": 7}`, false, false); code != http.StatusForbidden || body != `{"error":"forbidden"}` {
		t.Errorf("viewer: status %d: %s, want 403", code, body)
	}
	if code, _ := postLink(h, "/domains/new.x.example/link", "viewer", `{"campaign": 7}`, true, true); code != http.StatusForbidden {
		t.Errorf("viewer on the page route: status %d, want 403", code)
	}
	if len(f.imports) != 0 || len(f.updates) != 0 || len(f.campaigns) != 2 || len(a.got()) != 0 {
		t.Errorf("a refused request changed something: imports %v updates %v campaigns %d audit %v", f.imports, f.updates, len(f.campaigns), a.got())
	}
}

func TestLinkCampaign(t *testing.T) {
	h, f, a := linkTestServer(t)
	link := func(fqdn, body string) string {
		t.Helper()
		code, out := postLink(h, "/api/domains/"+fqdn+"/link", "analyst", body, false, false)
		if code != http.StatusOK {
			t.Fatalf("%s %s: status %d: %s", fqdn, body, code, out)
		}
		return out
	}

	if got, want := link("NEW.X.example.", `{"campaign": 7}`), `{"fqdn":"new.x.example","campaign":{"id":7,"name":"spynote"},"action":"added","created_campaign":false}`; got != want {
		t.Errorf("added:\n%s\nwant\n%s", got, want)
	}
	if want := []string{"new.x.example campaign 7 every 300s from api:ana by 2"}; !slices.Equal(f.imports, want) {
		t.Errorf("imports = %v, want %v", f.imports, want)
	}
	if got := link("new.x.example", `{"campaign": 7}`); !strings.Contains(got, `"action":"unchanged"`) {
		t.Errorf("same campaign again: %s", got)
	}
	if got := link("in.x.example", `{"campaign": 8}`); got != `{"fqdn":"in.x.example","campaign":{"id":8,"name":"other"},"action":"moved","created_campaign":false}` {
		t.Errorf("moved: %s", got)
	}
	if want := []string{"in.x.example campaign 8"}; !slices.Equal(f.updates, want) {
		t.Errorf("updates = %v, want %v", f.updates, want)
	}

	got := link("www.y.example", `{"new_campaign": {"name": " fresh ", "description": " seen in a phishing kit "}}`)
	if want := `{"fqdn":"www.y.example","campaign":{"id":12,"name":"fresh"},"action":"added","created_campaign":true}`; got != want {
		t.Errorf("new campaign:\n%s\nwant\n%s", got, want)
	}
	if c := f.campaigns[12]; c.Description != "seen in a phishing kit" || c.Family != "" {
		t.Errorf("created campaign %+v", c)
	}
	if got := link("in.x.example", `{"new_campaign": {"name": "fresh2"}}`); !strings.Contains(got, `"action":"moved","created_campaign":true`) {
		t.Errorf("watched name to a new campaign: %s", got)
	}

	want := []string{
		"domain.import spynote (new.x.example)",
		"domain.update in.x.example",
		"campaign.create fresh",
		"domain.import fresh (www.y.example)",
		"campaign.create fresh2",
		"domain.update in.x.example",
	}
	if got := a.got(); !slices.Equal(got, want) {
		t.Errorf("audit =\n%v\nwant\n%v", got, want)
	}
}

func TestLinkPageRoute(t *testing.T) {
	h, f, _ := linkTestServer(t)
	if code, _ := postLink(h, "/domains/page.x.example/link", "analyst", `{"campaign": 8}`, true, false); code != http.StatusForbidden {
		t.Errorf("without the CSRF token: status %d, want 403", code)
	}
	code, body := postLink(h, "/domains/page.x.example/link", "analyst", `{"campaign": 8}`, true, true)
	if code != http.StatusOK || !strings.Contains(body, `"action":"added"`) {
		t.Errorf("page route: status %d: %s", code, body)
	}
	if want := []string{"page.x.example campaign 8 every 300s from web:ana by 2"}; !slices.Equal(f.imports, want) {
		t.Errorf("imports = %v, want %v", f.imports, want)
	}
}

func TestGraphLinkDialog(t *testing.T) {
	s, g := graphTestServer(t)
	seven := int64(7)
	g.watched["www.x.example"] = pg.Domain{FQDN: "www.x.example", CampaignID: &seven, Campaign: "spynote"}
	s.links = newFakeLinkStore()
	h := withTokens(s)
	const current = `<input type="radio" name="link-choice" value="current" data-campaign="7"> Current campaign: spynote`

	for _, path := range []string{"/graph/domain/www.x.example", "/graph/campaign/7"} {
		code, body := serveSession(h, http.MethodGet, path, "analyst")
		for _, want := range []string{
			`<script src="/static/link.js" defer></script>`, `<dialog id="link-campaign" data-csrf="` + testCSRF + `">`, current,
			`<option value="8">other</option><option value="7">spynote</option>`,
			`<p class="notice" id="graph-enrich" data-label="Enrichment" aria-live="polite" hidden></p>`,
			`<li><span class="swatch-line swatch-cert"></span>CERT: name of a certificate</li>`,
		} {
			if code != http.StatusOK || !strings.Contains(body, want) {
				t.Errorf("%s as analyst: status %d, lacks %q", path, code, want)
			}
		}
	}

	_, body := serveSession(h, http.MethodGet, "/graph/ip/9.9.9.9", "analyst")
	if !strings.Contains(body, `<dialog id="link-campaign"`) || strings.Contains(body, `value="current"`) {
		t.Error("IP graph: no dialog, or a current campaign offered")
	}

	_, body = serveSession(h, http.MethodGet, "/graph/domain/www.x.example", "viewer")
	for _, unwanted := range []string{"link.js", "link-campaign", "graph-enrich"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("viewer: graph page has %s", unwanted)
		}
	}
}
