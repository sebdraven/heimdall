package scheduler

import (
	"fmt"
	"testing"
	"time"
)

func TestDue(t *testing.T) {
	s := New([]string{"A", "NS"}, 5*time.Minute, nil)
	s.Update([]Domain{
		{FQDN: "a.example", Interval: time.Minute},
		{FQDN: "b.example", Interval: time.Minute},
	}, []string{"9.9.9.9:53"})

	now := time.Now()
	jobs, _ := s.due(now.Add(time.Minute))
	if len(jobs) != 4 {
		t.Fatalf("first round: %d jobs, want 4", len(jobs))
	}
	if jobs, _ := s.due(now.Add(time.Minute)); len(jobs) != 0 {
		t.Fatalf("immediate second round: %d jobs, want 0", len(jobs))
	}
	if jobs, _ := s.due(now.Add(3 * time.Minute)); len(jobs) != 4 {
		t.Fatalf("next round: %d jobs, want 4", len(jobs))
	}

	s.Update([]Domain{{FQDN: "a.example", Interval: time.Minute}}, []string{"9.9.9.9:53"})
	if jobs, _ := s.due(now.Add(10 * time.Minute)); len(jobs) != 2 {
		t.Fatalf("after removal: %d jobs, want 2", len(jobs))
	}
}

var (
	t0        = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	qtypes    = []string{"A", "NS"}
	resolvers = []string{"9.9.9.9:53"}
)

func TestFirstRunWithinSpread(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		spread   time.Duration
		bound    time.Duration
	}{
		{"long interval capped by spread", 12 * time.Hour, 5 * time.Minute, 5 * time.Minute},
		{"short interval capped by itself", 2 * time.Minute, 5 * time.Minute, 2 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(qtypes, tt.spread, nil)
			var domains []Domain
			for i := range 200 {
				domains = append(domains, Domain{FQDN: fmt.Sprintf("d%d.example", i), Interval: tt.interval})
			}
			s.update(t0, domains, resolvers)
			for fqdn, e := range s.entries {
				if e.next.Before(t0) || !e.next.Before(t0.Add(tt.bound)) {
					t.Fatalf("%s first run at +%v, want within [0, %v)", fqdn, e.next.Sub(t0), tt.bound)
				}
			}
			if jobs, _ := s.due(t0.Add(tt.bound)); len(jobs) != len(domains)*len(qtypes)*len(resolvers) {
				t.Fatalf("at +%v: %d jobs, want every domain due", tt.bound, len(jobs))
			}
		})
	}
}

func TestNoResolverKeepsSlot(t *testing.T) {
	s := New(qtypes, 5*time.Minute, nil)
	d := []Domain{{FQDN: "a.example", Interval: 12 * time.Hour}}
	s.update(t0, d, nil)
	next := s.entries["a.example"].next

	later := t0.Add(time.Hour)
	jobs, wait := s.due(later)
	if len(jobs) != 0 || wait != idleWait {
		t.Fatalf("without resolver: %d jobs, wait %v; want 0, %v", len(jobs), wait, idleWait)
	}
	if got := s.entries["a.example"].next; !got.Equal(next) {
		t.Fatalf("next moved from %v to %v without any query", next, got)
	}

	s.update(later, d, resolvers)
	if jobs, _ := s.due(later); len(jobs) != len(qtypes) {
		t.Fatalf("after adding a resolver: %d jobs, want %d", len(jobs), len(qtypes))
	}
}

func TestNextRunAfterExecution(t *testing.T) {
	const interval = 10 * time.Minute
	s := New(qtypes, 5*time.Minute, nil)
	s.update(t0, []Domain{{FQDN: "a.example", Interval: interval}}, resolvers)
	run := t0.Add(5 * time.Minute)
	for range 100 {
		if jobs, _ := s.due(run); len(jobs) == 0 {
			t.Fatal("domain not due")
		}
		delay := s.entries["a.example"].next.Sub(run)
		if delay < 9*interval/10 || delay > 11*interval/10 {
			t.Fatalf("next run in %v, want within [0.9, 1.1] × %v", delay, interval)
		}
		run = s.entries["a.example"].next
	}
}

func TestJitter(t *testing.T) {
	for range 1000 {
		d := jitter(100 * time.Second)
		if d < 90*time.Second || d > 110*time.Second {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
}
