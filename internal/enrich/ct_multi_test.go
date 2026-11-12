package enrich

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// staticCT answers ct and err. With started, it closes it and waits for
// other first.
type staticCT struct {
	ct             *CT
	err            error
	started, other chan struct{}
	asked          int
}

func (s *staticCT) Lookup(context.Context, string) (*CT, error) {
	s.asked++
	if s.started != nil {
		close(s.started)
		select {
		case <-s.other:
		case <-time.After(5 * time.Second):
			return nil, errors.New("the other source was not asked meanwhile")
		}
	}
	return s.ct, s.err
}

func cert(id, sha string, notBefore time.Time, names ...string) Certificate {
	return Certificate{ID: id, CertSHA256: sha, Issuer: "Let's Encrypt", NotBefore: notBefore, NotAfter: notBefore.AddDate(0, 3, 0), Names: names}
}

func ctOf(truncated bool, certs ...Certificate) *CT {
	return (&CT{Zone: "x.example", Certificates: certs, Truncated: truncated}).finish()
}

var (
	jan = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	feb = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	mar = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	apr = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
)

func TestMultiCTMerge(t *testing.T) {
	shaPrefix := shaA[:63] + "0"
	fromOnyphe := cert("", shaA, jan.Add(time.Hour), "api.x.example", "www.x.example")
	fromOnyphe.Issuer = "YR2"
	fromOnyphe.NotAfter = apr
	onlyOnyphe := cert("", shaC, mar, "mail.x.example")
	onlyOnyphe.Issuer = "YR2"
	m := &MultiCT{
		CertSpotter: &staticCT{ct: ctOf(false, cert("1", strings.ToUpper(shaA), jan, "*.x.example", "www.x.example"), cert("2", shaB, feb, "old.x.example"))},
		Onyphe:      &staticCT{ct: ctOf(false, fromOnyphe, onlyOnyphe, cert("", shaPrefix, apr, "p.x.example"))},
	}
	ct, err := m.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if ct.Zone != "x.example" || ct.Total != 4 || len(ct.Certificates) != 4 || ct.Truncated {
		t.Fatalf("ct %+v", ct)
	}
	bySHA := map[string]Certificate{}
	var order []string
	for _, c := range ct.Certificates {
		bySHA[strings.ToLower(c.CertSHA256)] = c
		order = append(order, c.ID+"/"+strings.Join(c.Sources, "+"))
	}
	if want := []string{"/onyphe", "/onyphe", "2/certspotter", "1/certspotter+onyphe"}; !slices.Equal(order, want) {
		t.Errorf("order %v, want %v", order, want)
	}
	a := bySHA[shaA]
	if a.ID != "1" || a.Issuer != "Let's Encrypt" || !a.NotBefore.Equal(jan) || !a.NotAfter.Equal(jan.AddDate(0, 3, 0)) {
		t.Errorf("merged %+v, want the id, issuer and dates of Cert Spotter", a)
	}
	if !slices.Equal(a.Names, []string{"*.x.example", "api.x.example", "www.x.example"}) {
		t.Errorf("merged names %v, want the union", a.Names)
	}
	if c := bySHA[shaC]; c.Issuer != "YR2" || !c.NotBefore.Equal(mar) || !slices.Equal(c.Sources, []string{CTSourceOnyphe}) {
		t.Errorf("ONYPHE only %+v, want its own fields", c)
	}
	if p, ok := bySHA[shaPrefix]; !ok || len(p.CertSHA256) != 64 || !slices.Equal(p.Sources, []string{CTSourceOnyphe}) {
		t.Errorf("a SHA-256 sharing 63 characters with another was merged: %+v", p)
	}
	if want := []string{"*.x.example", "api.x.example", "mail.x.example", "old.x.example", "p.x.example", "www.x.example"}; !slices.Equal(ct.Names, want) {
		t.Errorf("names %v, want %v", ct.Names, want)
	}
	if src := m.CertSpotter.(*staticCT).ct.Certificates; src[1].Sources != nil || len(src[1].Names) != 2 {
		t.Errorf("source CT changed: %+v", src[1])
	}
}

func TestMultiCTParallel(t *testing.T) {
	a, b := make(chan struct{}), make(chan struct{})
	cs := &staticCT{ct: ctOf(false, cert("1", shaA, jan, "www.x.example")), started: a, other: b}
	on := &staticCT{ct: ctOf(false, cert("", shaB, feb, "api.x.example")), started: b, other: a}
	ct, err := (&MultiCT{CertSpotter: cs, Onyphe: on}).Lookup(context.Background(), "x.example")
	if err != nil || ct.Total != 2 {
		t.Errorf("%+v, %v, want both sources asked at once", ct, err)
	}
}

func TestMultiCTErrors(t *testing.T) {
	partial := ctOf(true, cert("1", shaA, jan, "www.x.example"))
	for _, tt := range []struct {
		desc      string
		cs, on    *staticCT
		want      string
		total     int
		truncated bool
	}{
		{
			"Cert Spotter partial",
			&staticCT{ct: partial, err: errors.New("cert spotter full-domain query quota exhausted, retry after 3600")},
			&staticCT{ct: ctOf(false, cert("", shaA, jan, "api.x.example"), cert("", shaB, feb, "b.x.example"))},
			"cert spotter full-domain query quota exhausted, retry after 3600", 2, true,
		},
		{
			"ONYPHE partial",
			&staticCT{ct: ctOf(false, cert("1", shaA, jan, "www.x.example"))},
			&staticCT{ct: ctOf(true, cert("", shaB, feb, "b.x.example")), err: errors.New("onyphe rate limited, retry after 60")},
			"onyphe rate limited, retry after 60", 2, true,
		},
		{
			"ONYPHE down",
			&staticCT{ct: ctOf(false, cert("1", shaA, jan, "www.x.example"))},
			&staticCT{err: errors.New("onyphe: HTTP 502")},
			"onyphe: HTTP 502", 1, false,
		},
		{
			"both failed, one partial",
			&staticCT{ct: partial, err: errors.New("cert spotter rate limited")},
			&staticCT{err: errors.New("onyphe: HTTP 401: Invalid API key")},
			"cert spotter rate limited; onyphe: HTTP 401: Invalid API key", 1, true,
		},
	} {
		ct, err := (&MultiCT{CertSpotter: tt.cs, Onyphe: tt.on}).Lookup(context.Background(), "x.example")
		if err == nil || err.Error() != tt.want {
			t.Errorf("%s: err %v, want %q", tt.desc, err, tt.want)
		}
		if ct == nil || ct.Total != tt.total || ct.Truncated != tt.truncated {
			t.Errorf("%s: ct %+v, want %d certificates, truncated %v", tt.desc, ct, tt.total, tt.truncated)
		}
	}

	ct, err := (&MultiCT{CertSpotter: &staticCT{err: errors.New("cert spotter: HTTP 502")}, Onyphe: &staticCT{err: errors.New("onyphe rate limited")}}).
		Lookup(context.Background(), "x.example")
	if ct != nil || err == nil || err.Error() != "cert spotter: HTTP 502; onyphe rate limited" {
		t.Errorf("both down: %+v, %v", ct, err)
	}
}

func TestMultiCTOneSource(t *testing.T) {
	cs := &staticCT{ct: ctOf(true, cert("1", shaA, jan, "www.x.example"))}
	ct, err := (&MultiCT{CertSpotter: cs}).Lookup(context.Background(), "x.example")
	if err != nil || cs.asked != 1 || ct.Total != 1 || !ct.Truncated || !slices.Equal(ct.Certificates[0].Sources, []string{CTSourceCertSpotter}) {
		t.Errorf("Cert Spotter alone: %+v, %v", ct, err)
	}

	cs = &staticCT{err: errors.New("cert spotter rate limited")}
	if ct, err := (&MultiCT{CertSpotter: cs}).Lookup(context.Background(), "x.example"); ct != nil || err == nil || err.Error() != "cert spotter rate limited" {
		t.Errorf("Cert Spotter alone, down: %+v, %v", ct, err)
	}

	on := &staticCT{ct: ctOf(false, cert("", shaB, feb, "api.x.example"))}
	if ct, err := (&MultiCT{Onyphe: on}).Lookup(context.Background(), "x.example"); err != nil || ct.Total != 1 || !slices.Equal(ct.Certificates[0].Sources, []string{CTSourceOnyphe}) {
		t.Errorf("ONYPHE alone: %+v, %v", ct, err)
	}

	if ct, err := (&MultiCT{}).Lookup(context.Background(), "x.example"); ct != nil || err == nil {
		t.Errorf("no source: %+v, %v", ct, err)
	}
}

func TestMultiCTCap(t *testing.T) {
	var older, newer []Certificate
	for i := range 400 {
		older = append(older, cert(fmt.Sprint(i), fmt.Sprintf("%064x", i+1), jan.Add(time.Duration(i)*time.Minute), "o.x.example"))
	}
	for i := range 200 {
		newer = append(newer, cert("", fmt.Sprintf("%064x", 1000+i), mar.Add(time.Duration(i)*time.Minute), "n.x.example"))
	}
	m := &MultiCT{CertSpotter: &staticCT{ct: ctOf(false, older...)}, Onyphe: &staticCT{ct: ctOf(false, newer...)}}
	ct, err := m.Lookup(context.Background(), "x.example")
	if err != nil {
		t.Fatal(err)
	}
	if ct.Total != MaxCertificates || len(ct.Certificates) != MaxCertificates || !ct.Truncated {
		t.Errorf("total %d kept %d truncated %v", ct.Total, len(ct.Certificates), ct.Truncated)
	}
	if first, last := ct.Certificates[0], ct.Certificates[MaxCertificates-1]; !first.NotBefore.Equal(mar.Add(199*time.Minute)) || last.ID != "100" {
		t.Errorf("kept %s to %s, want the latest %d", first.CertSHA256, last.ID, MaxCertificates)
	}
}
