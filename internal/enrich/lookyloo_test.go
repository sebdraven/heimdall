package enrich

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	uuidA = "0b6e7a52-6f0d-4a39-9d0c-3c1b1f6f8a01"
	uuidB = "5d2c9e14-8b7a-4c3f-a1e2-7f6d5c4b3a02"
	uuidC = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c03"
	uuidS = "c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e04"
)

var lookylooNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// fakeLookyloo answers the routes measured on the instance; any other is
// a 404 HTML page, as /json/<uuid>/ips is there.
type fakeLookyloo struct {
	t          *testing.T
	mu         sync.Mutex
	hits       string
	routes     map[string]string
	codes      map[string]int
	html       map[string]bool
	retryAfter string
	submit     string
	statuses   []string
	search     string
	submits    []string
	asked      []string
}

const notFoundHTML = "<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n"

func newFakeLookyloo(t *testing.T) *fakeLookyloo {
	return &fakeLookyloo{t: t, routes: map[string]string{}, codes: map[string]int{}, html: map[string]bool{}}
}

func (f *fakeLookyloo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if ua := r.Header.Get("User-Agent"); ua != "heimdall" {
		f.t.Errorf("User-Agent %q", ua)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, r.Method+" "+r.URL.Path)
	key := strings.TrimPrefix(r.URL.Path, "/json/")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/json/hostname_info":
		f.search = string(body)
	case r.Method == http.MethodPost && r.URL.Path == "/submit":
		f.submits = append(f.submits, string(body))
		key = "submit"
	case r.Method != http.MethodGet:
		key = ""
	}
	if code := f.codes[key]; code != 0 {
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		w.WriteHeader(code)
		return
	}
	if f.html[key] {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><body>maintenance</body></html>")
		return
	}
	answer, ok := f.routes[key]
	switch {
	case key == "hostname_info":
		answer, ok = f.hits, true
	case key == "submit":
		answer, ok = f.submit, true
	case strings.HasSuffix(key, "/status") && len(f.statuses) > 0:
		answer, ok, f.statuses = f.statuses[0], true, f.statuses[1:]
	}
	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, notFoundHTML)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, answer)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// capture serves the four routes of a capture in the forms measured.
func (f *fakeLookyloo) capture(uuid, start, title, at string, redirects, hostnames, urls []string) {
	f.routes[uuid+"/info"] = mustJSON(f.t, map[string]any{
		"uuid": uuid, "url": start, "title": title, "capture_time": at, "user_agent": "Mozilla/5.0 (X11; Linux x86_64)", "referer": "",
	})
	f.routes[uuid+"/redirects"] = mustJSON(f.t, map[string]any{"response": map[string]any{"url": start, "redirects": redirects}})
	f.routes[uuid+"/hostnames"] = mustJSON(f.t, map[string]any{"response": map[string]any{"hostnames": hostnames}})
	f.routes[uuid+"/urls"] = mustJSON(f.t, map[string]any{"response": map[string]any{"urls": urls}})
}

func hit(uuid, at, title string, hostnodes ...string) map[string]any {
	return map[string]any{"capture_uuid": uuid, "start_timestamp": at, "title": title, "hostnodes": hostnodes}
}

const (
	atA = "2026-11-13T06:30:20.390000+00:00"
	atB = "2026-10-01T10:00:00.000000+00:00"
	atC = "2026-06-01T08:00:00.123456+02:00"
	atS = "2026-11-14T12:00:30.000000+00:00"
)

// jjspyInstance holds two captures of jjspy.com, A and C, and one of
// other.example that loads it, B; hostname_info repeats a capture per
// hostnode, latest not first.
func jjspyInstance(t *testing.T) *fakeLookyloo {
	f := newFakeLookyloo(t)
	f.hits = mustJSON(t, []map[string]any{
		hit(uuidB, atB, "Other", "h1"), hit(uuidA, atA, "JJSpy", "h2"), hit(uuidC, atC, "JJSpy", "h3"),
		hit(uuidA, atA, "JJSpy", "h4"), hit(uuidB, atB, "Other", "h5"), hit(uuidB, atB, "Other", "h6"),
	})
	f.capture(uuidA, "https://jjspy.com/", "JJSpy", atA, []string{"https://www.jjspy.com/"},
		[]string{"jjspy.com", "WWW.JJSPY.COM", "www.google-analytics.com", "www.google.com", "jjspy.com"},
		[]string{"https://jjspy.com/", "https://www.jjspy.com/", jjspyUA, jjspyAdsList})
	f.capture(uuidB, "https://other.example/", "Other", atB, []string{},
		[]string{"other.example", "jjspy.com"},
		[]string{"https://other.example/", "https://jjspy.com/widget.js", "https://connect.facebook.net/signals/config/1234567890123456"})
	f.capture(uuidC, "https://jjspy.com/", "JJSpy", atC, []string{},
		[]string{"jjspy.com", "www.google-analytics.com"},
		[]string{"https://jjspy.com/", jjspyUA})
	return f
}

func lookylooClient(t *testing.T, f *fakeLookyloo, maxCaptures int, submit bool) *LookylooClient {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := NewLookylooClient(srv.URL+"/", maxCaptures, submit, DefaultLookylooMaxAge)
	c.Now = func() time.Time { return lookylooNow }
	c.PollEvery = time.Millisecond
	return c
}

func captureUUIDs(l *Lookyloo) []string {
	var out []string
	for _, c := range l.Captures {
		out = append(out, c.UUID)
	}
	return out
}

func (f *fakeLookyloo) requests() (search string, submits []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.search, slices.Clone(f.submits)
}

func (f *fakeLookyloo) askedMatching(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.asked {
		if strings.Contains(a, substr) {
			n++
		}
	}
	return n
}

func TestLookylooCaptures(t *testing.T) {
	f := jjspyInstance(t)
	c := lookylooClient(t, f, 10, false)
	l, err := c.Captures(context.Background(), "jjspy.com")
	if err != nil {
		t.Fatal(err)
	}
	if search, _ := f.requests(); search != `{"hostname":"jjspy.com","limit":40}` {
		t.Errorf("search %s, want limit 4 × MaxCaptures", search)
	}
	if l.Instance != c.BaseURL || strings.HasSuffix(l.Instance, "/") || l.CapturesFound != 3 || l.CapturesRead != 3 || l.Truncated || l.Submitted != nil {
		t.Errorf("lookyloo %+v", l)
	}
	if got := captureUUIDs(l); !slices.Equal(got, []string{uuidA, uuidB, uuidC}) {
		t.Errorf("captures %v, want one per uuid, latest first", got)
	}
	if n := f.askedMatching("/ips"); n != 0 {
		t.Errorf("asked /ips %d times", n)
	}
	if n := f.askedMatching(uuidA + "/"); n != 4 {
		t.Errorf("asked %d routes of a capture repeated by hostname_info, want 4", n)
	}

	a := l.Captures[0]
	at := time.Date(2026, 11, 13, 6, 30, 20, 390000000, time.UTC)
	if !a.Time.Equal(at) || a.Time.Location() != time.UTC || a.URL != "https://jjspy.com/" || a.Title != "JJSpy" || a.FinalURL != "https://www.jjspy.com/" {
		t.Errorf("capture A %+v", a)
	}
	if !slices.Equal(a.Redirects, []string{"https://www.jjspy.com/"}) ||
		!slices.Equal(a.Hostnames, []string{"jjspy.com", "www.google-analytics.com", "www.google.com", "www.jjspy.com"}) {
		t.Errorf("capture A redirects %v hostnames %v", a.Redirects, a.Hostnames)
	}
	if got := trackerIDs(a.Trackers); got != "gads AW-11021906314, ua UA-132944514-1" {
		t.Errorf("capture A trackers %s", got)
	}
	if cc := l.Captures[2]; !cc.Time.Equal(time.Date(2026, 6, 1, 6, 0, 0, 123456000, time.UTC)) || cc.Time.Location() != time.UTC || cc.FinalURL != "https://jjspy.com/" || cc.Redirects == nil {
		t.Errorf("capture C %+v, want its time in UTC and no redirect", cc)
	}
	if !l.Captures[1].Visits("other.example") || l.Captures[1].Visits("jjspy.com") {
		t.Error("capture B: wrong navigation")
	}
	if l.TreeURL(uuidA) != c.BaseURL+"/tree/"+uuidA {
		t.Errorf("tree %s", l.TreeURL(uuidA))
	}

	tA, tC := at, time.Date(2026, 6, 1, 6, 0, 0, 123456000, time.UTC)
	wantTrackers := []TrackerSeen{
		{Kind: TrackerGAds, ID: "AW-11021906314", FirstSeen: tA, LastSeen: tA, Captures: 1},
		{Kind: TrackerUA, ID: "UA-132944514-1", FirstSeen: tC, LastSeen: tA, Captures: 2},
	}
	if !slices.Equal(l.Trackers, wantTrackers) {
		t.Errorf("trackers %+v\nwant     %+v (not the pixel of other.example)", l.Trackers, wantTrackers)
	}
	wantHosts := []CaptureHost{
		{Name: "jjspy.com", FirstSeen: tC, LastSeen: tA},
		{Name: "www.google-analytics.com", FirstSeen: tC, LastSeen: tA},
		{Name: "www.google.com", FirstSeen: tA, LastSeen: tA},
		{Name: "www.jjspy.com", FirstSeen: tA, LastSeen: tA},
	}
	if !slices.Equal(l.Hosts, wantHosts) {
		t.Errorf("hosts %+v\nwant  %+v", l.Hosts, wantHosts)
	}

	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"instance":"` + c.BaseURL + `"`, `"captures_found":3`, `"captures_read":3`, `"truncated":false`, `"submitted":null`,
		`"final_url":"https://www.jjspy.com/"`, `{"kind":"ua","id":"UA-132944514-1","first_seen":"2026-06-01T06:00:00.123456Z","last_seen":"2026-11-13T06:30:20.39Z","captures":2}`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON lacks %s: %s", key, b)
		}
	}
}

func TestLookylooMaxCaptures(t *testing.T) {
	f := jjspyInstance(t)
	l, err := lookylooClient(t, f, 2, false).Captures(context.Background(), "jjspy.com")
	if err != nil {
		t.Fatal(err)
	}
	if search, _ := f.requests(); search != `{"hostname":"jjspy.com","limit":8}` {
		t.Errorf("search %s", search)
	}
	if !l.Truncated || l.CapturesFound != 3 || l.CapturesRead != 2 || !slices.Equal(captureUUIDs(l), []string{uuidA, uuidB}) {
		t.Errorf("lookyloo %+v, want the 2 latest, truncated", l)
	}
	if n := f.askedMatching(uuidC); n != 0 {
		t.Errorf("read the capture past MaxCaptures %d times", n)
	}
	if len(l.Trackers) != 2 || l.Trackers[1].Captures != 1 {
		t.Errorf("trackers %+v, want those of the captures read", l.Trackers)
	}

	f = newFakeLookyloo(t)
	f.hits = "[]"
	l, err = lookylooClient(t, f, 10, false).Captures(context.Background(), "jjspy.com")
	if err != nil || l.CapturesFound != 0 || l.CapturesRead != 0 || l.Truncated || l.Captures == nil || l.Trackers == nil || l.Hosts == nil {
		t.Errorf("no capture: %+v, %v, want an empty result and no error", l, err)
	}
}

func TestLookylooPartial(t *testing.T) {
	f := jjspyInstance(t)
	delete(f.routes, uuidA+"/urls")
	f.html[uuidB+"/hostnames"] = true
	l, err := lookylooClient(t, f, 10, false).Captures(context.Background(), "jjspy.com")
	if err == nil || !strings.HasPrefix(err.Error(), "lookyloo hostnames: decode: ") || !strings.HasSuffix(err.Error(), "; lookyloo urls: HTTP 404") {
		t.Errorf("err %v, want both routes named", err)
	}
	if l == nil || l.CapturesRead != 3 || l.Truncated {
		t.Fatalf("lookyloo %+v, want the captures kept", l)
	}
	a := l.Captures[0]
	if len(a.Trackers) != 0 || a.Trackers == nil || len(a.Hostnames) != 4 || a.FinalURL != "https://www.jjspy.com/" {
		t.Errorf("capture A %+v, want all but its trackers", a)
	}
	if b := l.Captures[1]; len(b.Hostnames) != 0 || b.Hostnames == nil || b.Title != "Other" {
		t.Errorf("capture B %+v", b)
	}
	if len(l.Trackers) != 1 || l.Trackers[0].Kind != TrackerUA || l.Trackers[0].ID != "UA-132944514-1" || l.Trackers[0].Captures != 1 {
		t.Errorf("trackers %+v, want those of C only", l.Trackers)
	}

	f = jjspyInstance(t)
	for _, route := range []string{"info", "redirects", "hostnames", "urls"} {
		f.codes[uuidB+"/"+route] = http.StatusBadGateway
	}
	l, err = lookylooClient(t, f, 10, false).Captures(context.Background(), "jjspy.com")
	if err == nil || err.Error() != "lookyloo hostnames: HTTP 502; lookyloo info: HTTP 502; lookyloo redirects: HTTP 502; lookyloo urls: HTTP 502" {
		t.Errorf("err %v", err)
	}
	if l == nil || !l.Truncated || l.CapturesFound != 3 || !slices.Equal(captureUUIDs(l), []string{uuidA, uuidC}) {
		t.Errorf("lookyloo %+v, want B left out, truncated", l)
	}

	f = jjspyInstance(t)
	f.codes["hostname_info"], f.retryAfter = http.StatusTooManyRequests, "30"
	if l, err := lookylooClient(t, f, 10, false).Captures(context.Background(), "jjspy.com"); l != nil || err == nil || err.Error() != "lookyloo hostname_info: rate limited, retry after 30" {
		t.Errorf("search rate limited: %+v, %v", l, err)
	}

	f = jjspyInstance(t)
	f.html["hostname_info"] = true
	if l, err := lookylooClient(t, f, 10, false).Captures(context.Background(), "jjspy.com"); l != nil || err == nil || !strings.HasPrefix(err.Error(), "lookyloo hostname_info: decode: ") {
		t.Errorf("search answered HTML: %+v, %v", l, err)
	}
}

func TestLookylooNoSubmit(t *testing.T) {
	f := jjspyInstance(t)
	f.hits = mustJSON(t, []map[string]any{hit(uuidB, atB, "Other"), hit(uuidC, atC, "JJSpy")})
	f.submit = `"` + uuidS + `"`
	l, err := lookylooClient(t, f, 10, false).Captures(context.Background(), "jjspy.com")
	if err != nil || l.CapturesRead != 2 || l.Submitted != nil {
		t.Errorf("%+v, %v", l, err)
	}
	if n := f.askedMatching("/submit"); n != 0 {
		t.Errorf("submitted %d times with HEIMDALL_LOOKYLOO_SUBMIT=false", n)
	}

	f = jjspyInstance(t)
	f.submit = `"` + uuidS + `"`
	_, err = lookylooClient(t, f, 10, true).Captures(context.Background(), "jjspy.com")
	if _, submits := f.requests(); err != nil || len(submits) != 0 {
		t.Errorf("submitted %v despite a capture of yesterday, err %v", submits, err)
	}
}

func TestLookylooSubmit(t *testing.T) {
	f := jjspyInstance(t)
	f.hits = mustJSON(t, []map[string]any{hit(uuidB, atB, "Other"), hit(uuidC, atC, "JJSpy")})
	f.submit = `"` + uuidS + `"` + "\n"
	f.statuses = []string{`{"status_code":0,"status_message":"queued"}`, `{"status_code":2,"status_message":"ongoing"}`, `{"status_code":1,"status_message":"done"}`}
	f.capture(uuidS, "https://jjspy.com/", "JJSpy", atS, []string{}, []string{"jjspy.com"}, []string{"https://jjspy.com/", jjspyAdsList})
	l, err := lookylooClient(t, f, 10, true).Captures(context.Background(), "jjspy.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, submits := f.requests(); len(submits) != 1 || submits[0] != `{"listing":false,"url":"https://jjspy.com/"}` {
		t.Errorf("submissions %v", submits)
	}
	if n := f.askedMatching(uuidS + "/status"); n != 3 {
		t.Errorf("status asked %d times, want until done", n)
	}
	if l.Submitted == nil || *l.Submitted != uuidS || l.CapturesFound != 3 || l.CapturesRead != 3 ||
		!slices.Equal(captureUUIDs(l), []string{uuidS, uuidB, uuidC}) {
		t.Errorf("lookyloo %+v, want the new capture first", l)
	}
	if s := l.Captures[0]; !s.Time.Equal(time.Date(2026, 11, 14, 12, 0, 30, 0, time.UTC)) || trackerIDs(s.Trackers) != "gads AW-11021906314" {
		t.Errorf("submitted capture %+v", s)
	}
}

func TestLookylooSubmitForms(t *testing.T) {
	for _, tt := range []struct{ body, want string }{
		{`"` + uuidS + `"`, uuidS},
		{`{"uuid":"` + uuidS + `"}`, uuidS},
		{`{"capture_uuid":"` + uuidS + `"}`, uuidS},
		{uuidS + "\n", uuidS},
		{`{"error":"invalid"}`, ""},
		{`"../../admin"`, ""},
		{"<html>", ""},
	} {
		if got := submittedUUID([]byte(tt.body)); got != tt.want {
			t.Errorf("submittedUUID(%s) = %q, want %q", tt.body, got, tt.want)
		}
	}
	for _, tt := range []struct {
		status string
		done   bool
	}{
		{`{"status_code":1,"status_message":"done"}`, true},
		{`{"status_code":2}`, false},
		{`{"status_code":-1}`, false},
		{`{"status":"ready"}`, true},
		{`1`, true},
		{`"done"`, true},
		{`0`, false},
		{`{}`, false},
	} {
		if got := captureDone(json.RawMessage(tt.status)); got != tt.done {
			t.Errorf("captureDone(%s) = %v", tt.status, got)
		}
	}
}
