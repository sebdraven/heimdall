package gjallarhorn

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

var (
	t0  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key = Key{Domain: "evil.example", QType: "A", Resolver: "9.9.9.9:53"}
)

func obsAt(d time.Duration, hash uint64, rcode string, ttl uint32, rdata ...string) Observation {
	if rdata == nil {
		rdata = []string{}
	}
	return Observation{Key: key, TS: t0.Add(d), Hash: hash, Rcode: rcode, Rdata: rdata, TTL: ttl}
}

func TestStep(t *testing.T) {
	base := State{TS: t0, Hash: 1, Rcode: "NOERROR", Rdata: []string{"192.0.2.1"}, TTL: 200, Ceiling: 300, WinStart: t0, WinMax: 200, WinN: 1}
	settled := base
	settled.Settled = true
	draining := settled
	draining.Ceiling, draining.WinMax, draining.WinN = 3600, 50, TTLWindowSamples-1

	tests := []struct {
		name       string
		prev       *State
		obs        Observation
		wantChange bool
		want       Change
		wantState  func(State) bool
	}{
		{
			name: "first observation",
			obs:  obsAt(0, 1, "NOERROR", 300, "192.0.2.1"),
		},
		{
			name: "same answer, ttl countdown",
			prev: &base,
			obs:  obsAt(time.Minute, 1, "NOERROR", 140, "192.0.2.1"),
		},
		{
			name:       "rdata change",
			prev:       &base,
			obs:        obsAt(time.Minute, 2, "NOERROR", 300, "192.0.2.2", "192.0.2.3"),
			wantChange: true,
			want: Change{
				PrevHash: 1, NewHash: 2, PrevRcode: "NOERROR", NewRcode: "NOERROR",
				Added: []string{"192.0.2.2", "192.0.2.3"}, Removed: []string{"192.0.2.1"},
				PrevTTL: 200, NewTTL: 300,
			},
		},
		{
			name:       "rcode change",
			prev:       &base,
			obs:        obsAt(time.Minute, 3, "NXDOMAIN", 0),
			wantChange: true,
			want: Change{
				PrevHash: 1, NewHash: 3, PrevRcode: "NOERROR", NewRcode: "NXDOMAIN",
				Added: []string{}, Removed: []string{"192.0.2.1"}, PrevTTL: 200, NewTTL: 0,
			},
		},
		{
			name:      "out of order observation ignored",
			prev:      &base,
			obs:       obsAt(-time.Minute, 2, "NOERROR", 300, "192.0.2.9"),
			wantState: func(s State) bool { return s.Hash == 1 },
		},
		{
			name:      "ttl above ceiling while learning",
			prev:      &base,
			obs:       obsAt(time.Minute, 1, "NOERROR", 900, "192.0.2.1"),
			wantState: func(s State) bool { return s.Ceiling == 900 },
		},
		{
			name:       "ttl raise once settled",
			prev:       &settled,
			obs:        obsAt(time.Minute, 1, "NOERROR", 900, "192.0.2.1"),
			wantChange: true,
			want: Change{
				PrevHash: 1, NewHash: 1, PrevRcode: "NOERROR", NewRcode: "NOERROR",
				Added: []string{}, Removed: []string{}, PrevTTL: 300, NewTTL: 900,
			},
		},
		{
			name: "ttl within raise factor once settled",
			prev: &settled,
			obs:  obsAt(time.Minute, 1, "NOERROR", 590, "192.0.2.1"),
		},
		{
			name:       "ttl drop after a full window",
			prev:       &draining,
			obs:        obsAt(3601*time.Second, 1, "NOERROR", 60, "192.0.2.1"),
			wantChange: true,
			want: Change{
				PrevHash: 1, NewHash: 1, PrevRcode: "NOERROR", NewRcode: "NOERROR",
				Added: []string{}, Removed: []string{}, PrevTTL: 3600, NewTTL: 60,
			},
		},
		{
			name:      "no ttl drop before the window spans the ceiling",
			prev:      &draining,
			obs:       obsAt(10*time.Minute, 1, "NOERROR", 60, "192.0.2.1"),
			wantState: func(s State) bool { return s.Ceiling == 3600 },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, ch := Step(tt.prev, tt.obs)
			if (ch != nil) != tt.wantChange {
				t.Fatalf("change = %+v, want change: %v", ch, tt.wantChange)
			}
			if ch != nil {
				tt.want.TS, tt.want.Key = tt.obs.TS, tt.obs.Key
				if !equalChange(*ch, tt.want) {
					t.Errorf("change = %+v\nwant     %+v", *ch, tt.want)
				}
			}
			if tt.wantState != nil && !tt.wantState(state) {
				t.Errorf("unexpected state %+v", state)
			}
		})
	}
}

func equalChange(a, b Change) bool {
	return a.TS.Equal(b.TS) && a.Key == b.Key &&
		a.PrevHash == b.PrevHash && a.NewHash == b.NewHash &&
		a.PrevRcode == b.PrevRcode && a.NewRcode == b.NewRcode &&
		slices.Equal(a.Added, b.Added) && slices.Equal(a.Removed, b.Removed) &&
		a.PrevTTL == b.PrevTTL && a.NewTTL == b.NewTTL
}

func TestTTLLearningSettles(t *testing.T) {
	s, _ := Step(nil, obsAt(0, 1, "NOERROR", 100, "192.0.2.1"))
	for i := 1; i < TTLWindowSamples; i++ {
		var ch *Change
		s, ch = Step(&s, obsAt(time.Duration(i)*time.Minute, 1, "NOERROR", 300, "192.0.2.1"))
		if ch != nil {
			t.Fatalf("sample %d: unexpected change %+v", i, ch)
		}
	}
	if !s.Settled || s.Ceiling != 300 {
		t.Fatalf("state after first window: %+v", s)
	}
}

func TestClassify(t *testing.T) {
	classes := []NSClass{
		{Pattern: "*.sinkhole.example.", Kind: NSKindSinkhole, Label: "LE sinkhole"},
		{Pattern: "parkingcrew.net", Kind: NSKindParking, Label: "ParkingCrew"},
	}
	ch := func(qtype, prevRcode, newRcode string, added, removed []string) Change {
		return Change{
			TS: t0, Key: Key{Domain: "evil.example", QType: qtype, Resolver: "9.9.9.9:53"},
			PrevHash: 1, NewHash: 2, PrevRcode: prevRcode, NewRcode: newRcode,
			Added: added, Removed: removed,
		}
	}
	none := []string{}

	tests := []struct {
		name string
		ch   Change
		want []string
	}{
		{"ttl only", Change{Key: key, PrevHash: 7, NewHash: 7, PrevRcode: "NOERROR", NewRcode: "NOERROR", PrevTTL: 3600, NewTTL: 60},
			[]string{KindTTLChange}},
		{"a records swapped", ch("A", "NOERROR", "NOERROR", []string{"192.0.2.2"}, []string{"192.0.2.1"}),
			[]string{KindNewRdata, KindRemovedRdata}},
		{"a records emptied", ch("A", "NOERROR", "NOERROR", none, []string{"192.0.2.1"}),
			[]string{KindRemovedRdata}},
		{"nxdomain on a", ch("A", "NOERROR", "NXDOMAIN", none, []string{"192.0.2.1"}),
			[]string{KindNXDomain}},
		{"nxdomain on mx", ch("MX", "NOERROR", "NXDOMAIN", none, []string{"10 mx.evil.example"}),
			none},
		{"resurrection on a", ch("A", "NXDOMAIN", "NOERROR", []string{"192.0.2.5"}, none),
			[]string{KindResurrection}},
		{"resurrection on txt", ch("TXT", "NXDOMAIN", "NOERROR", []string{`"x"`}, none),
			none},
		{"ns moved to sinkhole", ch("NS", "NOERROR", "NOERROR", []string{"ns1.sinkhole.example"}, []string{"ns1.registrar.example"}),
			[]string{KindNewRdata, KindRemovedRdata, KindNSSinkhole}},
		{"ns parking after nxdomain", ch("NS", "NXDOMAIN", "NOERROR", []string{"ns1.parkingcrew.net", "ns2.parkingcrew.net"}, none),
			[]string{KindNSParking}},
		{"ns unrelated", ch("NS", "NOERROR", "NOERROR", []string{"ns1.notsinkhole.example"}, none),
			[]string{KindNewRdata}},
		{"soa serial only", ch("SOA",
			"NOERROR", "NOERROR",
			[]string{"ns1.evil.example hostmaster.evil.example 2026010102 7200 3600 1209600 300"},
			[]string{"ns1.evil.example hostmaster.evil.example 2026010101 7200 3600 1209600 300"}),
			[]string{KindSOASerialChange}},
		{"soa mname and serial", ch("SOA",
			"NOERROR", "NOERROR",
			[]string{"ns1.sinkhole.example abuse.sinkhole.example 1 7200 3600 1209600 300"},
			[]string{"ns1.evil.example hostmaster.evil.example 2026010101 7200 3600 1209600 300"}),
			[]string{KindSOASerialChange, KindNewRdata, KindRemovedRdata}},
		{"noerror to other rcode", ch("A", "NOERROR", "FORMERR", none, []string{"192.0.2.1"}),
			none},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evs := Classify(tt.ch, "campaign-x", classes)
			got := []string{}
			for _, e := range evs {
				got = append(got, e.Kind)
				if e.Campaign != "campaign-x" || e.Domain != tt.ch.Domain || e.QType != tt.ch.QType {
					t.Errorf("event metadata not propagated: %+v", e)
				}
				if !json.Valid([]byte(e.Detail)) {
					t.Errorf("invalid detail JSON: %s", e.Detail)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("kinds = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClassifySinkholeDetail(t *testing.T) {
	evs := Classify(Change{
		Key: Key{Domain: "evil.example", QType: "NS"}, PrevHash: 1, NewHash: 2,
		PrevRcode: "NOERROR", NewRcode: "NOERROR", Added: []string{"ns1.sinkhole.example"},
	}, "", []NSClass{{Pattern: "sinkhole.example", Kind: NSKindSinkhole, Label: "LE"}})
	if len(evs) != 2 || evs[1].Kind != KindNSSinkhole {
		t.Fatalf("events = %+v", evs)
	}
	var d struct {
		Matches []map[string]string `json:"matches"`
	}
	if err := json.Unmarshal([]byte(evs[1].Detail), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Matches) != 1 || d.Matches[0]["ns"] != "ns1.sinkhole.example" || d.Matches[0]["label"] != "LE" {
		t.Errorf("detail = %s", evs[1].Detail)
	}
}

func TestSetDiff(t *testing.T) {
	tests := []struct {
		prev, cur, added, removed []string
	}{
		{nil, nil, []string{}, []string{}},
		{nil, []string{"b", "a"}, []string{"a", "b"}, []string{}},
		{[]string{"a", "b"}, []string{"b", "c"}, []string{"c"}, []string{"a"}},
		{[]string{"a"}, []string{"a"}, []string{}, []string{}},
	}
	for _, tt := range tests {
		added, removed := SetDiff(tt.prev, tt.cur)
		if !slices.Equal(added, tt.added) || !slices.Equal(removed, tt.removed) {
			t.Errorf("SetDiff(%v, %v) = %v, %v", tt.prev, tt.cur, added, removed)
		}
	}
}

func TestMatchNS(t *testing.T) {
	classes := []NSClass{{Pattern: "Sinkhole.Example.", Kind: NSKindSinkhole}}
	tests := map[string]bool{
		"sinkhole.example":        true,
		"ns1.sinkhole.example":    true,
		"a.b.sinkhole.example":    true,
		"notsinkhole.example":     false,
		"sinkhole.example.attack": false,
	}
	for ns, want := range tests {
		if _, got := MatchNS(ns, classes); got != want {
			t.Errorf("MatchNS(%q) = %v, want %v", ns, got, want)
		}
	}
}

func TestTransient(t *testing.T) {
	for rc, want := range map[string]bool{
		"TIMEOUT": true, "NETERR": true, "SERVFAIL": true, "REFUSED": true,
		"NOERROR": false, "NXDOMAIN": false,
	} {
		if got := Transient(rc); got != want {
			t.Errorf("Transient(%q) = %v, want %v", rc, got, want)
		}
	}
}
