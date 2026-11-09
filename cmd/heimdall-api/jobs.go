package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"
)

const jobKeep = time.Hour

const (
	jobRunning = "running"
	jobDone    = "done"
	jobFailed  = "failed"
	jobNone    = "none"
)

// job is the state of a background job. Result is set once it has
// finished; its fields are inlined in the JSON, before error.
type job[R any] struct {
	Target     string
	State      string
	StartedAt  *time.Time
	FinishedAt *time.Time
	Result     *R
	Error      string

	done chan struct{}
}

type jobHead struct {
	Target     string     `json:"job,omitempty"`
	State      string     `json:"state"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

type jobError struct {
	Error string `json:"error"`
}

func (j job[R]) MarshalJSON() ([]byte, error) {
	parts := []any{jobHead{j.Target, j.State, j.StartedAt, j.FinishedAt}}
	if j.Result != nil {
		parts = append(parts, j.Result)
	}
	if j.Error != "" {
		parts = append(parts, jobError{j.Error})
	}
	out := []byte{'{'}
	for _, p := range parts {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(p); err != nil {
			return nil, err
		}
		fields := bytes.TrimSpace(b.Bytes())
		if fields = fields[1 : len(fields)-1]; len(fields) == 0 {
			continue
		}
		if len(out) > 1 {
			out = append(out, ',')
		}
		out = append(out, fields...)
	}
	return append(out, '}'), nil
}

// jobs runs at most one job per target. A finished one is kept jobKeep.
type jobs[R any] struct {
	mu   sync.Mutex
	jobs map[string]*job[R]
	now  func() time.Time
}

func newJobs[R any]() *jobs[R] {
	return &jobs[R]{jobs: map[string]*job[R]{}, now: time.Now}
}

// prune forgets the jobs finished more than jobKeep ago. j.mu is held.
func (j *jobs[R]) prune() {
	cutoff := j.now().Add(-jobKeep)
	for t, job := range j.jobs {
		if job.FinishedAt != nil && job.FinishedAt.Before(cutoff) {
			delete(j.jobs, t)
		}
	}
}

func (j *jobs[R]) get(target string) (job[R], bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune()
	cur, ok := j.jobs[target]
	if !ok {
		return job[R]{}, false
	}
	return *cur, true
}

// begin registers a running job for target, unless one is running: started
// is false and cur is that one then.
func (j *jobs[R]) begin(target string) (cur job[R], started bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune()
	if c, ok := j.jobs[target]; ok && c.State == jobRunning {
		return *c, false
	}
	now := j.now()
	n := &job[R]{Target: target, State: jobRunning, StartedAt: &now, done: make(chan struct{})}
	j.jobs[target] = n
	return *n, true
}

// finish ends the running job of target; it failed when errMsg is set.
func (j *jobs[R]) finish(target string, res R, errMsg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	cur := j.jobs[target]
	now := j.now()
	cur.FinishedAt, cur.Result, cur.State = &now, &res, jobDone
	if errMsg != "" {
		cur.State, cur.Error = jobFailed, errMsg
	}
	close(cur.done)
}

// start runs work in the background for target unless a job of target is
// running, and returns the state of the target's job. work outlives the
// request of ctx, which a proxy may cut, for at most timeout; an errMsg
// fails the job.
func (j *jobs[R]) start(ctx context.Context, target string, timeout time.Duration, work func(context.Context) (R, string)) job[R] {
	cur, started := j.begin(target)
	if started {
		go func() {
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
			defer cancel()
			res, errMsg := work(wctx)
			j.finish(target, res, errMsg)
		}()
	}
	return cur
}
