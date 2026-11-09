package enrich

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const rdapExample = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "client transfer prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00+02:00"},
    {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:39Z"},
    {"eventAction": "last update of RDAP database", "eventDate": "2026-11-09T10:00:00Z"}
  ],
  "nameservers": [{"ldhName": "B.IANA-SERVERS.NET."}, {"ldhName": "A.IANA-SERVERS.NET"}],
  "entities": [{
    "roles": ["registrar"],
    "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]],
    "entities": [{
      "roles": ["abuse"],
      "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Abuse desk"],
        ["email", {}, "text", "abuse@example.net"], ["tel", {"type": "voice"}, "uri", "tel:+1.5555555"]]]
    }]
  }, {
    "roles": ["registrant"],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["org", {}, "text", "Example Org"], ["email", {}, "text", "owner@example.com"]]]
  }]
}`

// rdapServer serves the bootstrap at /dns.json, for com and net, and the
// domains of domains under /rdap/.
func rdapServer(t *testing.T, domains map[string]string) (*RDAPClient, *atomic.Int32) {
	t.Helper()
	var boot atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "heimdall" {
			t.Errorf("User-Agent %q", ua)
		}
		if r.URL.Path == "/dns.json" {
			boot.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"version": "1.0",
				"services": [][][]string{
					{{"com", "NET"}, {srv.URL + "/rdap", "http://other.invalid/rdap/"}},
					{{"empty"}, {}},
				},
			})
			return
		}
		body, ok := domains[strings.TrimPrefix(r.URL.Path, "/rdap/domain/")]
		if !ok || !strings.HasPrefix(r.URL.Path, "/rdap/domain/") {
			http.NotFound(w, r)
			return
		}
		if accept := r.Header.Get("Accept"); accept != "application/rdap+json" {
			t.Errorf("Accept %q", accept)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := NewRDAPClient()
	c.Bootstrap = srv.URL + "/dns.json"
	return c, &boot
}

func TestRDAPLookup(t *testing.T) {
	c, boot := rdapServer(t, map[string]string{"example.com": rdapExample})
	r, err := c.Lookup(context.Background(), "www.mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "example.com" || r.Registrar == nil || r.Registrar.Name != "RESERVED-Internet Assigned Numbers Authority" || r.Registrar.IANAID != "376" {
		t.Errorf("domain %s registrar %+v", r.Domain, r.Registrar)
	}
	if !r.Registration.Equal(time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC)) || !r.Expiration.Equal(time.Date(2027, 8, 13, 2, 0, 0, 0, time.UTC)) ||
		!r.LastChanged.Equal(time.Date(2026, 8, 14, 7, 1, 39, 0, time.UTC)) || r.Expiration.Location() != time.UTC {
		t.Errorf("dates %s %s %s", r.Registration, r.Expiration, r.LastChanged)
	}
	if got := strings.Join(r.Status, "|"); got != "client delete prohibited|client transfer prohibited" {
		t.Errorf("status = %s", got)
	}
	if got := strings.Join(r.Nameservers, " "); got != "a.iana-servers.net b.iana-servers.net" {
		t.Errorf("nameservers = %s", got)
	}
	b, _ := json.Marshal(r.Entities)
	if want := `[{"roles":["registrar"],"name":"RESERVED-Internet Assigned Numbers Authority"},{"roles":["abuse"],"name":"Abuse desk"},{"roles":["registrant"],"name":"Example Org"}]`; string(b) != want {
		t.Errorf("entities = %s\nwant       %s", b, want)
	}
	all, _ := json.Marshal(r)
	if strings.Contains(string(all), "@") || strings.Contains(string(all), "tel:") {
		t.Errorf("contact details kept: %s", all)
	}

	if _, err := c.Lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if n := boot.Load(); n != 1 {
		t.Errorf("bootstrap read %d times, want 1", n)
	}
	c.Now = func() time.Time { return time.Now().Add(bootstrapTTL) }
	if _, err := c.Lookup(context.Background(), "example.com"); err != nil || boot.Load() != 2 {
		t.Errorf("bootstrap not read again after %s: %d reads, err %v", bootstrapTTL, boot.Load(), err)
	}
}

func TestRDAPErrors(t *testing.T) {
	c, _ := rdapServer(t, map[string]string{"bad.net": "{"})
	for name, want := range map[string]string{
		"gone.example.com": "rdap example.com: HTTP 404",
		"x.bad.net":        "rdap bad.net: decode:",
		"x.example.org":    "no RDAP server for .org",
		"co.uk":            "no registrable domain for co.uk",
	} {
		if _, err := c.Lookup(context.Background(), name); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: err = %v, want %s", name, err, want)
		}
	}

	down := NewRDAPClient()
	down.Bootstrap = "http://127.0.0.1:1/dns.json"
	if _, err := down.Lookup(context.Background(), "example.com"); err == nil || !strings.HasPrefix(err.Error(), "rdap bootstrap:") {
		t.Errorf("bootstrap down: err = %v", err)
	}
}

func TestPickURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://a.example/rdap https://b.example/rdap/": "https://b.example/rdap/",
		"http://a.example/rdap":                         "http://a.example/rdap/",
		"":                                              "",
	} {
		if got := pickURL(strings.Fields(in)); got != want {
			t.Errorf("pickURL(%q) = %q, want %q", in, got, want)
		}
	}
}
