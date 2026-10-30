package scheduler

import (
	"testing"
	"time"
)

func TestDue(t *testing.T) {
	s := New([]string{"A", "NS"}, nil)
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

func TestJitter(t *testing.T) {
	for range 1000 {
		d := jitter(100 * time.Second)
		if d < 90*time.Second || d > 110*time.Second {
			t.Fatalf("jitter out of range: %v", d)
		}
	}
}
