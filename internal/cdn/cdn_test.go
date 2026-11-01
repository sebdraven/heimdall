package cdn

import (
	"net/netip"
	"testing"
)

func TestClassify(t *testing.T) {
	c := New([]Prefix{
		{Prefix: netip.MustParsePrefix("173.245.48.0/20"), Provider: "Cloudflare"},
		{Prefix: netip.MustParsePrefix("2606:4700::/32"), Provider: "Cloudflare"},
		{Prefix: netip.MustParsePrefix("173.245.60.0/24"), Provider: "Other"},
	})
	for addr, want := range map[string]string{
		"173.245.48.0":   "Cloudflare",
		"173.245.48.1":   "Cloudflare",
		"173.245.63.255": "Cloudflare",
		"173.245.47.255": "",
		"173.245.64.0":   "",
		"173.245.60.9":   "Other",

		"2606:4700::":                             "Cloudflare",
		"2606:4700::6810:84e5":                    "Cloudflare",
		"2606:4700:ffff:ffff:ffff:ffff:ffff:ffff": "Cloudflare",
		"2606:46ff:ffff:ffff:ffff:ffff:ffff:ffff": "",
		"2606:4701::":                             "",
		"::ffff:173.245.48.1":                     "Cloudflare",

		"cdn.cloudflare.net": "",
		"173.245.48.0/20":    "",
		`"173.245.48.1"`:     "",
		"10 173.245.48.1":    "",
		"":                   "",
	} {
		got, ok := c.Classify(addr)
		if got != want || ok != (want != "") {
			t.Errorf("Classify(%q) = %q, %v; want %q", addr, got, ok, want)
		}
	}
	if _, ok := (&Classifier{}).Classify("173.245.48.1"); ok {
		t.Error("empty classifier classified an address")
	}
}

func TestSet(t *testing.T) {
	c := New(nil)
	if _, ok := c.Classify("104.16.0.1"); ok {
		t.Fatal("classified with no prefixes")
	}
	c.Set([]Prefix{{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "Cloudflare"}})
	if p, ok := c.Classify("104.16.0.1"); !ok || p != "Cloudflare" {
		t.Errorf("after Set: %q, %v", p, ok)
	}
}

func TestParsePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"104.16.0.0/13":     "104.16.0.0/13",
		" 2400:cb00::/32 ":  "2400:cb00::/32",
		"192.0.2.7":         "192.0.2.7/32",
		"2001:db8::1":       "2001:db8::1/128",
		"::ffff:192.0.2.7":  "192.0.2.7/32",
		"104.16.0.1/13":     "",
		"2001:db8::1/32":    "",
		"::ffff:0.0.0.0/96": "",
		"fe80::1%eth0":      "",
		"104.16.0.0/33":     "",
		"cdn.example":       "",
		"":                  "",
	} {
		p, err := ParsePrefix(in)
		if want == "" {
			if err == nil {
				t.Errorf("ParsePrefix(%q) = %s, want an error", in, p)
			}
			continue
		}
		if err != nil || p.String() != want {
			t.Errorf("ParsePrefix(%q) = %s, %v; want %s", in, p, err, want)
		}
	}
}
