package cof

import (
	"bytes"
	"testing"
	"time"
)

func TestWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	first := time.Date(2026, 1, 1, 0, 0, 0, 500_000_000, time.UTC)
	last := first.Add(time.Hour)
	for _, r := range []Record{
		New("evil.example", "A", "192.0.2.1", first, last, 12),
		New("evil.example", "TXT", `"<b>&"`, first, last, 1),
	} {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	want := `{"rrname":"evil.example","rrtype":"A","rdata":"192.0.2.1","time_first":1767225600,"time_last":1767229200,"count":12}
{"rrname":"evil.example","rrtype":"TXT","rdata":"\"<b>&\"","time_first":1767225600,"time_last":1767229200,"count":1}
`
	if got := buf.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
