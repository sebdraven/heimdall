package scheduler

import (
	"container/heap"
	"context"
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

const (
	jitterRatio     = 0.10
	defaultInterval = 5 * time.Minute
	idleWait        = time.Hour
)

type Domain struct {
	FQDN     string
	Campaign string
	Interval time.Duration
}

type Job struct {
	Domain   string
	Campaign string
	QType    string
	Resolver string
}

type Scheduler struct {
	qtypes []string
	out    chan<- Job
	wake   chan struct{}

	mu        sync.Mutex
	entries   map[string]*entry
	queue     queue
	resolvers []string
}

func New(qtypes []string, out chan<- Job) *Scheduler {
	return &Scheduler{
		qtypes:  slices.Clone(qtypes),
		out:     out,
		wake:    make(chan struct{}, 1),
		entries: make(map[string]*entry),
	}
}

// Update replaces the watchlist. New domains are spread over their first
// interval to avoid a burst at startup.
func (s *Scheduler) Update(domains []Domain, resolvers []string) {
	now := time.Now()
	s.mu.Lock()
	seen := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if d.Interval <= 0 {
			d.Interval = defaultInterval
		}
		seen[d.FQDN] = struct{}{}
		if e, ok := s.entries[d.FQDN]; ok {
			shorter := d.Interval < e.Interval
			e.Domain = d
			if limit := now.Add(jitter(d.Interval)); shorter && e.next.After(limit) {
				e.next = limit
				heap.Fix(&s.queue, e.index)
			}
			continue
		}
		e := &entry{Domain: d, next: now.Add(time.Duration(rand.Int64N(int64(d.Interval))))}
		s.entries[d.FQDN] = e
		heap.Push(&s.queue, e)
	}
	for fqdn, e := range s.entries {
		if _, ok := seen[fqdn]; !ok {
			heap.Remove(&s.queue, e.index)
			delete(s.entries, fqdn)
		}
	}
	s.resolvers = slices.Clone(resolvers)
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Scheduler) Run(ctx context.Context) {
	timer := time.NewTimer(idleWait)
	defer timer.Stop()
	for {
		jobs, wait := s.due(time.Now())
		for _, j := range jobs {
			select {
			case s.out <- j:
			case <-ctx.Done():
				return
			}
		}
		if len(jobs) > 0 {
			continue
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
	}
}

func (s *Scheduler) due(now time.Time) ([]Job, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var jobs []Job
	for s.queue.Len() > 0 {
		e := s.queue[0]
		if e.next.After(now) {
			break
		}
		for _, r := range s.resolvers {
			for _, qt := range s.qtypes {
				jobs = append(jobs, Job{Domain: e.FQDN, Campaign: e.Campaign, QType: qt, Resolver: r})
			}
		}
		e.next = now.Add(jitter(e.Interval))
		heap.Fix(&s.queue, e.index)
	}
	if s.queue.Len() == 0 {
		return jobs, idleWait
	}
	return jobs, s.queue[0].next.Sub(now)
}

func jitter(d time.Duration) time.Duration {
	f := 1 - jitterRatio + 2*jitterRatio*rand.Float64()
	return time.Duration(float64(d) * f)
}

type entry struct {
	Domain
	next  time.Time
	index int
}

type queue []*entry

func (q queue) Len() int           { return len(q) }
func (q queue) Less(i, j int) bool { return q[i].next.Before(q[j].next) }
func (q queue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}

func (q *queue) Push(x any) {
	e := x.(*entry)
	e.index = len(*q)
	*q = append(*q, e)
}

func (q *queue) Pop() any {
	old := *q
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	*q = old[:n-1]
	return e
}
