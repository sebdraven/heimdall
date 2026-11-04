package main

import (
	"strconv"
	"sync"
	"time"

	"github.com/sebdraven/heimdall/internal/vt"
)

const (
	vtJobTimeout = 10 * time.Minute
	vtJobKeep    = time.Hour
)

const (
	vtRunning = "running"
	vtDone    = "done"
	vtFailed  = "failed"
	vtNone    = "none"
)

// vtJob is the state of a VirusTotal enrichment. The summary fields are set
// once it has finished.
type vtJob struct {
	Target     string     `json:"job,omitempty"`
	State      string     `json:"state"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	*vt.Summary
	Error string `json:"error,omitempty"`

	done chan struct{}
}

func domainTarget(fqdn string) string { return "domain:" + fqdn }

func campaignTarget(id int64) string { return "campaign:" + strconv.FormatInt(id, 10) }

// vtJobs holds the enrichments, at most one running per target. A finished
// one is kept vtJobKeep.
type vtJobs struct {
	mu   sync.Mutex
	jobs map[string]*vtJob
	now  func() time.Time
}

func newVTJobs() *vtJobs {
	return &vtJobs{jobs: map[string]*vtJob{}, now: time.Now}
}

// prune forgets the jobs finished more than vtJobKeep ago. j.mu is held.
func (j *vtJobs) prune() {
	cutoff := j.now().Add(-vtJobKeep)
	for t, job := range j.jobs {
		if job.FinishedAt != nil && job.FinishedAt.Before(cutoff) {
			delete(j.jobs, t)
		}
	}
}

func (j *vtJobs) get(target string) (vtJob, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune()
	job, ok := j.jobs[target]
	if !ok {
		return vtJob{}, false
	}
	return *job, true
}

// begin registers a running job for target, unless one is running: started
// is false and job is that one then.
func (j *vtJobs) begin(target string) (job vtJob, started bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune()
	if cur, ok := j.jobs[target]; ok && cur.State == vtRunning {
		return *cur, false
	}
	now := j.now()
	n := &vtJob{Target: target, State: vtRunning, StartedAt: &now, done: make(chan struct{})}
	j.jobs[target] = n
	return *n, true
}

// finish ends the running job of target; it failed when errMsg is set.
func (j *vtJobs) finish(target string, sum vt.Summary, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	job := j.jobs[target]
	now := j.now()
	job.FinishedAt, job.Summary, job.State = &now, &sum, vtDone
	if errMsg != "" {
		job.State, job.Error = vtFailed, errMsg
	}
	close(job.done)
}
