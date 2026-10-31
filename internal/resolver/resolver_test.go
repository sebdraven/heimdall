package resolver

import (
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		rr   string
		want string
	}{
		{"example.com. 300 IN A 192.0.2.1", "192.0.2.1"},
		{"example.com. 300 IN AAAA 2001:DB8::1", "2001:db8::1"},
		{"www.example.com. 60 IN CNAME Target.Example.NET.", "target.example.net"},
		{"example.com. 3600 IN NS NS1.Example.COM.", "ns1.example.com"},
		{"example.com. 3600 IN MX 10 MX.Example.COM.", "10 mx.example.com"},
		{`example.com. 300 IN TXT "v=spf1 -all" "Second"`, `"v=spf1 -all" "Second"`},
		{"example.com. 3600 IN SOA NS1.Example.com. Hostmaster.Example.com. 2024010101 7200 3600 1209600 300",
			"ns1.example.com hostmaster.example.com 2024010101 7200 3600 1209600 300"},
	}
	for _, tt := range tests {
		rr, err := dns.NewRR(tt.rr)
		if err != nil {
			t.Fatalf("NewRR(%q): %v", tt.rr, err)
		}
		if got := Normalize(rr); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.rr, got, tt.want)
		}
	}
}

func TestExtract(t *testing.T) {
	m := new(dns.Msg)
	for _, s := range []string{
		"WWW.Example.com. 300 IN CNAME Edge.Example.NET.",
		"edge.example.net. 120 IN A 192.0.2.2",
		"edge.example.net. 60 IN A 192.0.2.1",
		"edge.example.net. 60 IN A 192.0.2.1",
	} {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = append(m.Answer, rr)
	}
	rdata, ttl := Extract(m, dns.TypeA)
	if want := []string{"192.0.2.1", "192.0.2.2"}; !slices.Equal(rdata, want) {
		t.Errorf("rdata = %v, want %v", rdata, want)
	}
	if ttl != 60 {
		t.Errorf("ttl = %d, want 60", ttl)
	}
	if rdata, ttl := Extract(new(dns.Msg), dns.TypeA); len(rdata) != 0 || ttl != 0 {
		t.Errorf("empty answer: rdata = %v, ttl = %d", rdata, ttl)
	}

	wantAnswers := []Answer{
		{Name: "edge.example.net", Type: "A", Value: "192.0.2.1"},
		{Name: "edge.example.net", Type: "A", Value: "192.0.2.2"},
		{Name: "www.example.com", Type: "CNAME", Value: "edge.example.net"},
	}
	if got := Answers(m); !slices.Equal(got, wantAnswers) {
		t.Errorf("answers = %+v, want %+v", got, wantAnswers)
	}
	if got := Answers(new(dns.Msg)); len(got) != 0 {
		t.Errorf("empty answer: answers = %+v", got)
	}
}

func TestAuthorityAndZone(t *testing.T) {
	msg := func(rrs ...string) *dns.Msg {
		m := new(dns.Msg)
		for _, s := range rrs {
			rr, err := dns.NewRR(s)
			if err != nil {
				t.Fatal(err)
			}
			m.Ns = append(m.Ns, rr)
		}
		return m
	}
	tests := []struct {
		name string
		msg  *dns.Msg
		want []Answer
		zone string
	}{
		{
			name: "nodata with soa",
			msg: msg(
				"SyamCloud.com. 900 IN SOA NS1.syamcloud.com. hostmaster.syamcloud.com. 2026103101 7200 3600 1209600 300",
				"syamcloud.com. 900 IN SOA ns1.syamcloud.com. hostmaster.syamcloud.com. 2026103101 7200 3600 1209600 300",
			),
			want: []Answer{{Name: "syamcloud.com", Type: "SOA", Value: "ns1.syamcloud.com hostmaster.syamcloud.com 2026103101 7200 3600 1209600 300"}},
			zone: "syamcloud.com",
		},
		{
			name: "ns only",
			msg: msg(
				"syamcloud.com. 3600 IN NS ns2.example.net.",
				"syamcloud.com. 3600 IN NS NS1.example.net.",
				"ns1.example.net. 3600 IN A 192.0.2.53",
			),
			want: []Answer{
				{Name: "syamcloud.com", Type: "NS", Value: "ns1.example.net"},
				{Name: "syamcloud.com", Type: "NS", Value: "ns2.example.net"},
			},
			zone: "syamcloud.com",
		},
		{
			name: "soa preferred over ns",
			msg: msg(
				"com. 900 IN NS a.gtld-servers.net.",
				"syamcloud.com. 900 IN SOA ns1.syamcloud.com. hostmaster.syamcloud.com. 1 7200 3600 1209600 300",
			),
			want: []Answer{
				{Name: "com", Type: "NS", Value: "a.gtld-servers.net"},
				{Name: "syamcloud.com", Type: "SOA", Value: "ns1.syamcloud.com hostmaster.syamcloud.com 1 7200 3600 1209600 300"},
			},
			zone: "syamcloud.com",
		},
		{name: "no authority", msg: new(dns.Msg), want: []Answer{}, zone: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Authority(tt.msg)
			if !slices.Equal(got, tt.want) {
				t.Errorf("authority = %+v, want %+v", got, tt.want)
			}
			if z := Zone(got); z != tt.zone {
				t.Errorf("zone = %q, want %q", z, tt.zone)
			}
		})
	}
}

func TestAnswerHash(t *testing.T) {
	a := AnswerHash("NOERROR", []string{"192.0.2.1", "192.0.2.2"})
	b := AnswerHash("NOERROR", []string{"192.0.2.2", "192.0.2.1"})
	if a != b {
		t.Error("hash depends on rdata order")
	}
	if a == AnswerHash("NXDOMAIN", []string{"192.0.2.1", "192.0.2.2"}) {
		t.Error("hash ignores rcode")
	}
	if AnswerHash("NOERROR", []string{"ab", "c"}) == AnswerHash("NOERROR", []string{"a", "bc"}) {
		t.Error("hash is ambiguous across value boundaries")
	}
}

func TestNormalizeFQDN(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Example.COM.", "example.com", true},
		{" sub.example.com ", "sub.example.com", true},
		{"_dmarc.example.com", "_dmarc.example.com", true},
		{"localhost", "", false},
		{"exa mple.com", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, err := NormalizeFQDN(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("NormalizeFQDN(%q) = %q, %v", tt.in, got, err)
		}
	}
}

func TestNormalizeServer(t *testing.T) {
	tests := map[string]string{
		"9.9.9.9":          "9.9.9.9:53",
		"1.1.1.1:5353":     "1.1.1.1:5353",
		"2620:fe::fe":      "[2620:fe::fe]:53",
		"[2620:fe::fe]:53": "[2620:fe::fe]:53",
	}
	for in, want := range tests {
		if got, err := NormalizeServer(in); err != nil || got != want {
			t.Errorf("NormalizeServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
