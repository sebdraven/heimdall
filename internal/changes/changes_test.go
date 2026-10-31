package gjallarhorn

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/resolver"
)

const grace = 3

var (
	t0  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key = keyFor("A")
)

func keyFor(qtype string) Key {
	return Key{Domain: "evil.example", QType: qtype, Resolver: "9.9.9.9:53"}
}

func obsAt(qtype string, d time.Duration, rcode string, ttl uint32, rdata ...string) Observation {
	if rdata == nil {
		rdata = []string{}
	}
	return Observation{Key: keyFor(qtype), TS: t0.Add(d), Rcode: rcode, Rdata: rdata, TTL: ttl}
}

func stateOf(rcode string, ttl uint32, tracked ...string) State {
	if tracked == nil {
		tracked = []string{}
	}
	slices.Sort(tracked)
	return State{
		TS:       t0,
		Rcode:    rcode,
		Tracked:  tracked,
		Missing:  make([]uint32, len(tracked)),
		Hash:     resolver.AnswerHash(rcode, tracked),
		TTL:      ttl,
		Ceiling:  300,
		WinStart: t0,
		WinMax:   ttl,
		WinN:     1,
	}
}

func TestStep(t *testing.T) {
	base := stateOf("NOERROR", 200, "192.0.2.1")
	two := stateOf("NOERROR", 200, "192.0.2.1", "192.0.2.2")
	twoMissing := two
	twoMissing.Missing = []uint32{0, grace - 1}
	nx := stateOf("NXDOMAIN", 0)
	soa := stateOf("NOERROR", 200, "ns1.evil.example h.evil.example 1 7200 3600 1209600 300")
	cname := stateOf("NOERROR", 200, "a.cdn.example")
	settled := base
	settled.Settled = true
	draining := settled
	draining.Ceiling, draining.WinMax, draining.WinN = 3600, 50, TTLWindowSamples-1

	type wantChange struct {
		added, removed  []string
		prevTTL, newTTL uint32
	}
	none := []string{}

	tests := []struct {
		name  string
		prev  *State
		obs   Observation
		want  *wantChange
		check func(State) bool
	}{
		{
			name:  "first observation",
			obs:   obsAt("A", 0, "NOERROR", 300, "192.0.2.2", "192.0.2.1"),
			check: func(s State) bool { return slices.Equal(s.Tracked, []string{"192.0.2.1", "192.0.2.2"}) },
		},
		{
			name: "same answer, ttl countdown",
			prev: &base,
			obs:  obsAt("A", time.Minute, "NOERROR", 140, "192.0.2.1"),
		},
		{
			name: "addition is immediate",
			prev: &base,
			obs:  obsAt("A", time.Minute, "NOERROR", 300, "192.0.2.1", "192.0.2.2"),
			want: &wantChange{added: []string{"192.0.2.2"}, removed: none, prevTTL: 200, newTTL: 300},
		},
		{
			name: "absence within grace keeps the value",
			prev: &two,
			obs:  obsAt("A", time.Minute, "NOERROR", 300, "192.0.2.1"),
			check: func(s State) bool {
				return slices.Equal(s.Tracked, two.Tracked) && slices.Equal(s.Missing, []uint32{0, 1})
			},
		},
		{
			name:  "removal when the absence count reaches grace",
			prev:  &twoMissing,
			obs:   obsAt("A", time.Minute, "NOERROR", 300, "192.0.2.1"),
			want:  &wantChange{added: none, removed: []string{"192.0.2.2"}, prevTTL: 200, newTTL: 300},
			check: func(s State) bool { return slices.Equal(s.Tracked, []string{"192.0.2.1"}) },
		},
		{
			name:  "returning value resets its count",
			prev:  &twoMissing,
			obs:   obsAt("A", time.Minute, "NOERROR", 300, "192.0.2.2", "192.0.2.1"),
			check: func(s State) bool { return slices.Equal(s.Missing, []uint32{0, 0}) },
		},
		{
			name:  "nxdomain empties the tracked set",
			prev:  &twoMissing,
			obs:   obsAt("A", time.Minute, "NXDOMAIN", 0),
			want:  &wantChange{added: none, removed: []string{"192.0.2.1", "192.0.2.2"}, prevTTL: 200, newTTL: 0},
			check: func(s State) bool { return len(s.Tracked) == 0 && s.Rcode == "NXDOMAIN" },
		},
		{
			name: "resurrection is immediate",
			prev: &nx,
			obs:  obsAt("A", time.Minute, "NOERROR", 300, "192.0.2.5"),
			want: &wantChange{added: []string{"192.0.2.5"}, removed: none, prevTTL: 0, newTTL: 300},
		},
		{
			name: "soa has no hysteresis",
			prev: &soa,
			obs:  obsAt("SOA", time.Minute, "NOERROR", 300, "ns1.evil.example h.evil.example 2 7200 3600 1209600 300"),
			want: &wantChange{
				added:   []string{"ns1.evil.example h.evil.example 2 7200 3600 1209600 300"},
				removed: []string{"ns1.evil.example h.evil.example 1 7200 3600 1209600 300"},
				prevTTL: 200, newTTL: 300,
			},
		},
		{
			name: "cname has no hysteresis",
			prev: &cname,
			obs:  obsAt("CNAME", time.Minute, "NOERROR", 300, "b.cdn.example"),
			want: &wantChange{added: []string{"b.cdn.example"}, removed: []string{"a.cdn.example"}, prevTTL: 200, newTTL: 300},
		},
		{
			name:  "out of order observation ignored",
			prev:  &base,
			obs:   obsAt("A", -time.Minute, "NOERROR", 300, "192.0.2.9"),
			check: func(s State) bool { return slices.Equal(s.Tracked, []string{"192.0.2.1"}) },
		},
		{
			name:  "ttl above ceiling while learning",
			prev:  &base,
			obs:   obsAt("A", time.Minute, "NOERROR", 900, "192.0.2.1"),
			check: func(s State) bool { return s.Ceiling == 900 },
		},
		{
			name: "ttl raise once settled",
			prev: &settled,
			obs:  obsAt("A", time.Minute, "NOERROR", 900, "192.0.2.1"),
			want: &wantChange{added: none, removed: none, prevTTL: 300, newTTL: 900},
		},
		{
			name: "ttl within raise factor once settled",
			prev: &settled,
			obs:  obsAt("A", time.Minute, "NOERROR", 590, "192.0.2.1"),
		},
		{
			name: "ttl drop after a full window",
			prev: &draining,
			obs:  obsAt("A", 3601*time.Second, "NOERROR", 60, "192.0.2.1"),
			want: &wantChange{added: none, removed: none, prevTTL: 3600, newTTL: 60},
		},
		{
			name:  "no ttl drop before the window spans the ceiling",
			prev:  &draining,
			obs:   obsAt("A", 10*time.Minute, "NOERROR", 60, "192.0.2.1"),
			check: func(s State) bool { return s.Ceiling == 3600 },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, ch := Step(tt.prev, tt.obs, grace)
			if (ch != nil) != (tt.want != nil) {
				t.Fatalf("change = %+v, want %+v", ch, tt.want)
			}
			if ch != nil {
				if !slices.Equal(ch.Added, tt.want.added) || !slices.Equal(ch.Removed, tt.want.removed) ||
					ch.PrevTTL != tt.want.prevTTL || ch.NewTTL != tt.want.newTTL {
					t.Errorf("change = %+v, want %+v", *ch, *tt.want)
				}
				if ch.Key != tt.obs.Key || !ch.TS.Equal(tt.obs.TS) || ch.NewRcode != tt.obs.Rcode {
					t.Errorf("change metadata = %+v", *ch)
				}
				setChanged := len(ch.Added)+len(ch.Removed) > 0 || ch.PrevRcode != ch.NewRcode
				if setChanged == (ch.PrevTrackedHash == ch.NewTrackedHash) {
					t.Errorf("hashes %d -> %d inconsistent with set change %v", ch.PrevTrackedHash, ch.NewTrackedHash, setChanged)
				}
				if ch.NewTrackedHash != state.Hash || state.Hash != resolver.AnswerHash(state.Rcode, state.Tracked) {
					t.Errorf("state hash %d does not cover (rcode, tracked)", state.Hash)
				}
			}
			if tt.check != nil && !tt.check(state) {
				t.Errorf("unexpected state %+v", state)
			}
		})
	}
}

func TestHysteresisSequences(t *testing.T) {
	type step struct {
		rcode string
		rdata []string
	}
	ok := func(v ...string) step { return step{"NOERROR", v} }
	nx := step{rcode: "NXDOMAIN"}
	type diff struct{ added, removed []string }
	none := []string{}

	tests := []struct {
		name  string
		qtype string
		grace int
		steps []step
		want  map[int]diff
	}{
		{
			name: "rotating pool served by pairs", qtype: "A", grace: 3,
			steps: []step{ok("a", "b"), ok("b", "c"), ok("a", "c"), ok("a", "b"), ok("b", "c"), ok("a", "c"), ok("a", "b")},
			want:  map[int]diff{1: {[]string{"c"}, none}},
		},
		{
			name: "grace 1 disables hysteresis", qtype: "A", grace: 1,
			steps: []step{ok("a", "b"), ok("b", "c")},
			want:  map[int]diff{1: {[]string{"c"}, []string{"a"}}},
		},
		{
			name: "real removal reported once at grace", qtype: "A", grace: 3,
			steps: []step{ok("a", "b"), ok("a"), ok("a"), ok("a"), ok("a"), ok("a")},
			want:  map[int]diff{3: {none, []string{"b"}}},
		},
		{
			name: "value back before grace", qtype: "AAAA", grace: 3,
			steps: []step{ok("a", "b"), ok("a"), ok("a"), ok("a", "b"), ok("a"), ok("a")},
			want:  map[int]diff{},
		},
		{
			name: "addition is immediate", qtype: "NS", grace: 3,
			steps: []step{ok("ns1.example"), ok("ns1.example", "ns2.example")},
			want:  map[int]diff{1: {[]string{"ns2.example"}, none}},
		},
		{
			name: "empty answer counts as an absence", qtype: "MX", grace: 3,
			steps: []step{ok("10 mx.example"), ok(), ok(), ok()},
			want:  map[int]diff{3: {none, []string{"10 mx.example"}}},
		},
		{
			name: "nxdomain empties the set, resurrection refills from the answer", qtype: "TXT", grace: 3,
			steps: []step{ok("a", "b"), ok("a"), nx, ok("a")},
			want:  map[int]diff{2: {none, []string{"a", "b"}}, 3: {[]string{"a"}, none}},
		},
		{
			name: "soa without hysteresis", qtype: "SOA", grace: 3,
			steps: []step{ok("s1"), ok("s2"), ok("s2"), ok("s1")},
			want:  map[int]diff{1: {[]string{"s2"}, []string{"s1"}}, 3: {[]string{"s1"}, []string{"s2"}}},
		},
		{
			name: "cname without hysteresis", qtype: "CNAME", grace: 3,
			steps: []step{ok("x.example"), ok("y.example")},
			want:  map[int]diff{1: {[]string{"y.example"}, []string{"x.example"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s *State
			for i, st := range tt.steps {
				next, ch := Step(s, obsAt(tt.qtype, time.Duration(i)*time.Minute, st.rcode, 300, st.rdata...), tt.grace)
				s = &next
				want, wantChange := tt.want[i]
				if (ch != nil) != wantChange {
					t.Fatalf("step %d: change = %+v, want change: %v", i, ch, wantChange)
				}
				if ch != nil && (!slices.Equal(ch.Added, want.added) || !slices.Equal(ch.Removed, want.removed)) {
					t.Errorf("step %d: added %v removed %v, want %v %v", i, ch.Added, ch.Removed, want.added, want.removed)
				}
			}
		})
	}
}

func TestTrack(t *testing.T) {
	tests := []struct {
		grace       int
		wantTracked []string
		wantMissing []uint32
	}{
		{3, []string{"a", "b", "c"}, []uint32{2, 0, 0}},
		{2, []string{"b", "c"}, []uint32{0, 0}},
	}
	for _, tt := range tests {
		tracked, missing := Track([]string{"a", "b"}, []uint32{1, 3}, []string{"b", "c"}, tt.grace)
		if !slices.Equal(tracked, tt.wantTracked) || !slices.Equal(missing, tt.wantMissing) {
			t.Errorf("grace %d: Track = %v %v, want %v %v", tt.grace, tracked, missing, tt.wantTracked, tt.wantMissing)
		}
	}
}

func TestTTLLearningSettles(t *testing.T) {
	s, _ := Step(nil, obsAt("A", 0, "NOERROR", 100, "192.0.2.1"), grace)
	for i := 1; i < TTLWindowSamples; i++ {
		var ch *Change
		s, ch = Step(&s, obsAt("A", time.Duration(i)*time.Minute, "NOERROR", 300, "192.0.2.1"), grace)
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
			TS: t0, Key: keyFor(qtype),
			PrevTrackedHash: 1, NewTrackedHash: 2, PrevRcode: prevRcode, NewRcode: newRcode,
			Added: added, Removed: removed,
		}
	}
	none := []string{}

	tests := []struct {
		name string
		ch   Change
		want []string
	}{
		{"ttl only", Change{Key: key, PrevTrackedHash: 7, NewTrackedHash: 7, PrevRcode: "NOERROR", NewRcode: "NOERROR", PrevTTL: 3600, NewTTL: 60},
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
		Key: keyFor("NS"), PrevTrackedHash: 1, NewTrackedHash: 2,
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
