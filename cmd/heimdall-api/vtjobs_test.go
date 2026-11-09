package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sebdraven/heimdall/internal/vt"
)

var vtJobTime = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// blockingLookup answers once release is closed, or fails with its context.
type blockingLookup struct {
	release chan struct{}
	err     error
	calls   atomic.Int32
}

func (l *blockingLookup) DomainResolutions(ctx context.Context, _ string) ([]vt.Resolution, error) {
	return l.wait(ctx)
}

func (l *blockingLookup) IPResolutions(ctx context.Context, _ string) ([]vt.Resolution, error) {
	return l.wait(ctx)
}

func (l *blockingLookup) wait(ctx context.Context) ([]vt.Resolution, error) {
	l.calls.Add(1)
	select {
	case <-l.release:
		return nil, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// openLedger never refuses a lookup and keeps nothing.
type openLedger struct{}

func (openLedger) ReserveVTLookup(context.Context, int) (bool, error) { return true, nil }

func (openLedger) VTUsageToday(context.Context) (int, error) { return 0, nil }

func (openLedger) FreshVTObjects(context.Context, []string, time.Time) (map[string]bool, error) {
	return nil, nil
}

func (openLedger) RecordVTFetch(context.Context, string, string, int) error { return nil }

func (openLedger) InsertVTResolutions(context.Context, []vt.Resolution, time.Time) error { return nil }

type fakeAudit struct {
	mu      sync.Mutex
	entries []string
}

func (f *fakeAudit) Audit(_ context.Context, _ *int64, action, target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, action+" "+target)
	return nil
}

func (f *fakeAudit) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.entries)
}

func vtJobServer(t *testing.T) (*server, *blockingLookup, *fakeAudit) {
	t.Helper()
	s, _ := graphTestServer(t)
	l := &blockingLookup{release: make(chan struct{})}
	a := &fakeAudit{}
	s.vt = &vt.Enricher{
		Lookup: l,
		Ledger: openLedger{},
		Sink:   openLedger{},
		CDN:    s.cdn,
		Budget: 500,
		TTL:    time.Hour,
		Log:    s.log,
	}
	s.vtJobs.now = func() time.Time { return vtJobTime }
	s.audits = a
	return s, l, a
}

func serveVT(ctx context.Context, h http.HandlerFunc, method string) (int, string) {
	r := httptest.NewRequestWithContext(ctx, method, "/graph/domain/www.x.example/vt?depth=1", nil)
	r.SetPathValue("fqdn", "www.x.example")
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec.Code, strings.TrimSpace(rec.Body.String())
}

func waitVTJob(t *testing.T, s *server, target string) {
	t.Helper()
	job, ok := s.vtJobs.get(target)
	if !ok {
		t.Fatalf("no job for %s", target)
	}
	select {
	case <-job.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("job %s still running", target)
	}
}

func TestEnrichGraphBackground(t *testing.T) {
	s, l, a := vtJobServer(t)
	bg := context.Background()
	running := `{"job":"domain:www.x.example","state":"running","started_at":"2026-11-04T12:00:00Z"}`

	if code, body := serveVT(bg, s.vtJobDomain, http.MethodGet); code != http.StatusOK || body != `{"state":"none"}` {
		t.Errorf("GET before: status %d: %s", code, body)
	}

	// The request is cut as soon as it is answered, like a proxy timeout.
	ctx, cancel := context.WithCancel(bg)
	code, body := serveVT(ctx, s.enrichGraphDomain, http.MethodPost)
	cancel()
	if code != http.StatusAccepted || body != running {
		t.Errorf("POST: status %d: %s, want 202 %s", code, body, running)
	}
	if code, body := serveVT(bg, s.enrichGraphDomain, http.MethodPost); code != http.StatusAccepted || body != running {
		t.Errorf("second POST: status %d: %s, want 202 %s", code, body, running)
	}
	if _, body := serveVT(bg, s.vtJobDomain, http.MethodGet); body != running {
		t.Errorf("GET while running: %s", body)
	}
	if got := a.got(); len(got) != 0 {
		t.Errorf("audited before the end: %v", got)
	}

	close(l.release)
	waitVTJob(t, s, domainTarget("www.x.example"))
	done := `{"job":"domain:www.x.example","state":"done","started_at":"2026-11-04T12:00:00Z","finished_at":"2026-11-04T12:00:00Z",` +
		`"looked_up":2,"cached":0,"skipped_cdn":0,"skipped_reserved":1,"skipped_budget":0,"stopped_reason":""}`
	if _, body := serveVT(bg, s.vtJobDomain, http.MethodGet); body != done {
		t.Errorf("GET after:\n%s\nwant\n%s", body, done)
	}
	if n := l.calls.Load(); n != 2 {
		t.Errorf("%d lookups, want 2: one job, not cut by the request", n)
	}
	want := []string{"vt.enrich domain www.x.example (looked up 2, cached 0, skipped for budget 0)"}
	if got := a.got(); !slices.Equal(got, want) {
		t.Errorf("audit = %v, want %v", got, want)
	}
}

func TestEnrichGraphFailed(t *testing.T) {
	s, l, a := vtJobServer(t)
	l.err = errors.New("connection reset")
	close(l.release)
	if code, _ := serveVT(context.Background(), s.enrichGraphDomain, http.MethodPost); code != http.StatusAccepted {
		t.Fatalf("POST: status %d", code)
	}
	waitVTJob(t, s, domainTarget("www.x.example"))
	if _, body := serveVT(context.Background(), s.vtJobDomain, http.MethodGet); !strings.Contains(body, `"state":"failed"`) ||
		!strings.HasSuffix(body, `"error":"internal error"}`) {
		t.Errorf("GET after a failure: %s", body)
	}
	if got := a.got(); len(got) != 1 || !strings.HasSuffix(got[0], ", failed)") {
		t.Errorf("audit = %v", got)
	}
}

func TestVTJobCampaignDisabled(t *testing.T) {
	s, _ := graphTestServer(t)
	if code, _ := serveGraph(t, s, s.vtJobCampaign, "/graph/campaign/7/vt", "id", "7"); code != http.StatusNotFound {
		t.Errorf("GET without VirusTotal: status %d, want 404", code)
	}
}

func TestVTJobsForget(t *testing.T) {
	j := newJobs[vt.Summary]()
	now := vtJobTime
	j.now = func() time.Time { return now }
	const target = "campaign:7"

	if _, started := j.begin(target); !started {
		t.Fatal("first job not started")
	}
	if job, started := j.begin(target); started || job.State != jobRunning {
		t.Errorf("second begin: started %v, state %s", started, job.State)
	}
	now = now.Add(2 * jobKeep)
	if _, ok := j.get(target); !ok {
		t.Error("running job forgotten")
	}
	j.finish(target, vt.Summary{LookedUp: 1}, "")
	now = now.Add(jobKeep)
	if job, ok := j.get(target); !ok || job.State != jobDone || job.Result.LookedUp != 1 {
		t.Errorf("finished job %+v, kept %v", job, ok)
	}
	now = now.Add(time.Second)
	if _, ok := j.get(target); ok {
		t.Error("finished job kept past jobKeep")
	}
	if _, started := j.begin(target); !started {
		t.Error("no new job after the last one finished")
	}
}
