package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestJobJSON(t *testing.T) {
	at := vtJobTime
	for _, tt := range []struct {
		job  job[enrichSummary]
		want string
	}{
		{job[enrichSummary]{State: jobNone}, `{"state":"none"}`},
		{
			job[enrichSummary]{Target: "domain:x.example", State: jobFailed, StartedAt: &at, FinishedAt: &at,
				Result: &enrichSummary{Status: "error", Summary: "error: <dns> failed"}, Error: "internal error"},
			`{"job":"domain:x.example","state":"failed","started_at":"2026-11-04T12:00:00Z","finished_at":"2026-11-04T12:00:00Z",` +
				`"status":"error","counts":{"dns":0,"rdap":0,"ct":0,"subdomains":0,"lookyloo":0},"summary":"error: <dns> failed","error":"internal error"}`,
		},
	} {
		if got := encode(t, tt.job); got != tt.want {
			t.Errorf("job JSON =\n%s\nwant\n%s", got, tt.want)
		}
	}
}

func TestJobsStart(t *testing.T) {
	j := newJobs[enrichSummary]()
	j.now = func() time.Time { return vtJobTime }
	release := make(chan struct{})
	var runs atomic.Int32
	var deadline atomic.Bool
	work := func(ctx context.Context) (enrichSummary, string) {
		runs.Add(1)
		_, ok := ctx.Deadline()
		deadline.Store(ok)
		select {
		case <-release:
			return enrichSummary{Status: "ok"}, ""
		case <-ctx.Done():
			return enrichSummary{}, "cut"
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	first := j.start(ctx, "domain:x.example", time.Minute, work)
	cancel()
	second := j.start(context.Background(), "domain:x.example", time.Minute, work)
	if first.State != jobRunning || second.State != jobRunning || !first.StartedAt.Equal(*second.StartedAt) {
		t.Errorf("first %+v second %+v, want the same running job", first, second)
	}
	close(release)
	cur, _ := j.get("domain:x.example")
	select {
	case <-cur.done:
	case <-time.After(5 * time.Second):
		t.Fatal("job still running")
	}
	if cur, _ = j.get("domain:x.example"); cur.State != jobDone || cur.Result.Status != "ok" || cur.Error != "" {
		t.Errorf("job %+v, want done: not cut by the request", cur)
	}
	if runs.Load() != 1 || !deadline.Load() {
		t.Errorf("%d runs, deadline %v; want 1 with a deadline", runs.Load(), deadline.Load())
	}
}
