package ch

import (
	"testing"
	"time"
)

func TestCurrentSOA(t *testing.T) {
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	p := func(from, to int) Period { return Period{First: at.AddDate(0, 0, from), Last: at.AddDate(0, 0, to)} }
	z := currentSOA("x.example", []soaRecord{
		{"x.example", "ns1.old.example. admin.old.example. 1 7200 900 1209600 300", p(0, 5)},
		{"x.example", "NS1.X.example. Admin.X.example. 3 7200 900 1209600 300", p(4, 9)},
		{"x.example", "ns1.x.example. admin.x.example. 2 7200 900 1209600 300", p(2, 4)},
		{"x.example", "garbage", p(0, 10)},
	})
	if z == nil || z.Zone != "x.example" || z.MName != "ns1.x.example" || z.RName != "admin.x.example" ||
		!z.Period.First.Equal(at.AddDate(0, 0, 2)) || !z.Period.Last.Equal(at.AddDate(0, 0, 9)) {
		t.Errorf("soa = %+v, want the latest pair over both serials", z)
	}
	if z := currentSOA("x.example", nil); z != nil {
		t.Errorf("no record: %+v", z)
	}
}
