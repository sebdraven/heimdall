package main

import (
	"slices"
	"testing"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func obs(i int, rcode string, ttl uint32, rdata ...string) resolver.Observation {
	if rdata == nil {
		rdata = []string{}
	}
	return resolver.Observation{
		TS: t0.Add(time.Duration(i) * time.Minute), Domain: "evil.example", QType: "A", Resolver: "9.9.9.9:53",
		Rcode: rcode, Rdata: rdata, TTL: ttl,
	}
}

var tupleKey = gjallarhorn.Key{Domain: "evil.example", QType: "A", Resolver: "9.9.9.9:53"}

func TestTransientRcodes(t *testing.T) {
	for _, rc := range []string{"TIMEOUT", "NETERR", "SERVFAIL", "REFUSED"} {
		if !gjallarhorn.Transient(rc) {
			t.Errorf("%s is not transient", rc)
		}
	}
}

func TestObserveSkipsTransient(t *testing.T) {
	tests := []struct {
		name  string
		seq   []resolver.Observation
		final func(gjallarhorn.State) bool
	}{
		{
			name: "servfail between two identical answers",
			seq: []resolver.Observation{
				obs(0, "NOERROR", 300, "192.0.2.1"),
				obs(1, "SERVFAIL", 0),
				obs(2, "NOERROR", 300, "192.0.2.1"),
			},
			final: func(s gjallarhorn.State) bool { return s.Rcode == "NOERROR" && slices.Equal(s.Tracked, []string{"192.0.2.1"}) },
		},
		{
			name: "transients do not advance absence counters",
			seq: []resolver.Observation{
				obs(0, "NOERROR", 300, "192.0.2.1", "192.0.2.2"),
				obs(1, "NOERROR", 300, "192.0.2.1"),
				obs(2, "SERVFAIL", 0),
				obs(3, "TIMEOUT", 0),
				obs(4, "REFUSED", 0),
				obs(5, "NETERR", 0),
				obs(6, "NOERROR", 300, "192.0.2.1"),
			},
			final: func(s gjallarhorn.State) bool {
				return slices.Equal(s.Tracked, []string{"192.0.2.1", "192.0.2.2"}) && slices.Equal(s.Missing, []uint32{0, 2})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := newTracker(3)
			for i, o := range tt.seq {
				changes, events, release := tr.observe(o, "", nil)
				release()
				if len(changes) != 0 || len(events) != 0 {
					t.Fatalf("observation %d (%s): changes %+v events %+v", i, o.Rcode, changes, events)
				}
			}
			if s := tr.state[tupleKey]; !tt.final(s) {
				t.Errorf("final state %+v", s)
			}
		})
	}
}

func TestDirtySnapshots(t *testing.T) {
	tr := newTracker(3)
	snapLen := func() int { return len(tr.snapshot()) }
	see := func(o resolver.Observation) {
		_, _, release := tr.observe(o, "", nil)
		release()
	}

	see(obs(0, "NOERROR", 300, "192.0.2.1"))
	if n := snapLen(); n != 1 {
		t.Fatalf("first state: %d tuples, want 1", n)
	}
	see(obs(1, "NOERROR", 240, "192.0.2.1"))
	if n := snapLen(); n != 0 {
		t.Fatalf("ttl countdown only: %d tuples, want 0", n)
	}
	see(obs(2, "SERVFAIL", 0))
	if n := snapLen(); n != 0 {
		t.Fatalf("transient: %d tuples, want 0", n)
	}
	see(obs(3, "NOERROR", 300, "192.0.2.1", "192.0.2.2"))
	see(obs(4, "NOERROR", 300, "192.0.2.1"))
	snap := tr.snapshot()
	if len(snap) != 1 || !slices.Equal(snap[0].State.Missing, []uint32{0, 1}) {
		t.Fatalf("one row per tuple with the latest state, got %+v", snap)
	}

	tr.requeue(snap)
	if n := snapLen(); n != 1 {
		t.Fatalf("after requeue: %d tuples, want 1", n)
	}

	see(obs(5, "NOERROR", 300, "192.0.2.3"))
	tr.prune(map[string]struct{}{})
	if n := snapLen(); n != 0 {
		t.Fatalf("after prune: %d tuples, want 0", n)
	}
}

func TestSnapshotWaitsForPendingItem(t *testing.T) {
	tr := newTracker(3)
	_, _, release := tr.observe(obs(0, "NOERROR", 300, "192.0.2.1"), "", nil)
	if n := len(tr.snapshot()); n != 0 {
		t.Fatalf("snapshot taken before the item reached the writer: %d tuples", n)
	}
	release()
	if n := len(tr.snapshot()); n != 1 {
		t.Fatalf("after release: %d tuples, want 1", n)
	}
	if _, _, release := tr.observe(obs(1, "SERVFAIL", 0), "", nil); release != nil {
		release()
	}
	if len(tr.pending) != 0 {
		t.Fatalf("pending not cleared: %v", tr.pending)
	}
}
