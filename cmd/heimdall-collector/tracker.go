package main

import (
	"context"
	"log/slog"
	"slices"
	"sync"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
)

// tracker holds the detection state per (domain, qtype, resolver) and the
// keys whose state changed since the last snapshot. pending counts the
// observations whose item has not reached the writer yet: their state must
// not be snapshotted before their changes and events.
type tracker struct {
	grace int

	mu      sync.Mutex
	state   map[gjallarhorn.Key]gjallarhorn.State
	dirty   map[gjallarhorn.Key]struct{}
	pending map[gjallarhorn.Key]int
}

func newTracker(grace int) *tracker {
	return &tracker{
		grace:   grace,
		state:   make(map[gjallarhorn.Key]gjallarhorn.State),
		dirty:   make(map[gjallarhorn.Key]struct{}),
		pending: make(map[gjallarhorn.Key]int),
	}
}

func noRelease() {}

func (t *tracker) load(ctx context.Context, chs *ch.Store, log *slog.Logger) error {
	rows, err := chs.LoadStates(ctx)
	if err != nil {
		return err
	}
	state := make(map[gjallarhorn.Key]gjallarhorn.State, len(rows))
	for _, r := range rows {
		state[r.Key] = r.State
	}
	t.mu.Lock()
	t.state = state
	clear(t.dirty)
	t.mu.Unlock()
	log.Info("state restored", "tuples", len(state))
	return nil
}

// observe updates the tuple state. release must be called once the item
// carrying the returned changes and events has been handed to the writer.
func (t *tracker) observe(obs resolver.Observation, campaign string, classes []gjallarhorn.NSClass) (changes []gjallarhorn.Change, events []gjallarhorn.Event, release func()) {
	if gjallarhorn.Transient(obs.Rcode) {
		return nil, nil, noRelease
	}
	o := gjallarhorn.Observation{
		Key:   gjallarhorn.Key{Domain: obs.Domain, QType: obs.QType, Resolver: obs.Resolver},
		TS:    obs.TS,
		Rcode: obs.Rcode,
		Rdata: obs.Rdata,
		TTL:   obs.TTL,
	}
	t.mu.Lock()
	var prev *gjallarhorn.State
	if s, ok := t.state[o.Key]; ok {
		prev = &s
	}
	next, change := gjallarhorn.Step(prev, o, t.grace)
	t.state[o.Key] = next
	if prev == nil || persistedFieldsDiffer(*prev, next) {
		t.dirty[o.Key] = struct{}{}
	}
	t.pending[o.Key]++
	t.mu.Unlock()

	release = func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if n := t.pending[o.Key] - 1; n > 0 {
			t.pending[o.Key] = n
		} else {
			delete(t.pending, o.Key)
		}
	}
	if change == nil {
		return nil, nil, release
	}
	return []gjallarhorn.Change{*change}, gjallarhorn.Classify(*change, campaign, classes), release
}

// persistedFieldsDiffer ignores TS, TTL and the TTL window, which move on
// every observation: persisting them alone would write one row per query.
func persistedFieldsDiffer(a, b gjallarhorn.State) bool {
	return a.Rcode != b.Rcode || a.Hash != b.Hash || a.Ceiling != b.Ceiling || a.Settled != b.Settled ||
		!slices.Equal(a.Tracked, b.Tracked) || !slices.Equal(a.Missing, b.Missing)
}

// snapshot returns the current state of every dirty key, at most once per
// key, and removes them from the dirty set. Keys with a pending item stay
// dirty for the next snapshot.
func (t *tracker) snapshot() []ch.TupleState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ch.TupleState, 0, len(t.dirty))
	for k := range t.dirty {
		if t.pending[k] > 0 {
			continue
		}
		if s, ok := t.state[k]; ok {
			out = append(out, ch.TupleState{Key: k, State: s})
		}
		delete(t.dirty, k)
	}
	return out
}

// requeue marks the tuples of a failed snapshot dirty again.
func (t *tracker) requeue(lost []ch.TupleState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range lost {
		if _, ok := t.state[s.Key]; ok {
			t.dirty[s.Key] = struct{}{}
		}
	}
}

func (t *tracker) prune(watched map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.state {
		if _, ok := watched[k.Domain]; !ok {
			delete(t.state, k)
			delete(t.dirty, k)
		}
	}
}
