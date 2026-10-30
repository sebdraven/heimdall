package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
)

// tracker holds the last known state per (domain, qtype, resolver).
type tracker struct {
	mu    sync.Mutex
	state map[gjallarhorn.Key]gjallarhorn.State
}

func newTracker() *tracker {
	return &tracker{state: make(map[gjallarhorn.Key]gjallarhorn.State)}
}

func (t *tracker) load(ctx context.Context, chs *ch.Store, log *slog.Logger) error {
	rows, err := chs.LoadState(ctx, stateWindow, gjallarhorn.TransientRcodes)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	state := make(map[gjallarhorn.Key]gjallarhorn.State, len(rows))
	for _, r := range rows {
		state[r.Key] = gjallarhorn.State{
			TS:       r.TS,
			Hash:     r.Hash,
			Rcode:    r.Rcode,
			Rdata:    r.Rdata,
			TTL:      r.TTL,
			Ceiling:  max(r.MaxTTL, r.TTL),
			Settled:  r.Samples >= gjallarhorn.TTLWindowSamples,
			WinStart: now,
		}
	}
	t.mu.Lock()
	t.state = state
	t.mu.Unlock()
	log.Info("state restored", "tuples", len(state))
	return nil
}

func (t *tracker) observe(obs resolver.Observation, campaign string, classes []gjallarhorn.NSClass) ([]gjallarhorn.Change, []gjallarhorn.Event) {
	if gjallarhorn.Transient(obs.Rcode) {
		return nil, nil
	}
	o := gjallarhorn.Observation{
		Key:   gjallarhorn.Key{Domain: obs.Domain, QType: obs.QType, Resolver: obs.Resolver},
		TS:    obs.TS,
		Hash:  obs.AnswerHash,
		Rcode: obs.Rcode,
		Rdata: obs.Rdata,
		TTL:   obs.TTL,
	}
	t.mu.Lock()
	var prev *gjallarhorn.State
	if s, ok := t.state[o.Key]; ok {
		prev = &s
	}
	next, change := gjallarhorn.Step(prev, o)
	t.state[o.Key] = next
	t.mu.Unlock()

	if change == nil {
		return nil, nil
	}
	return []gjallarhorn.Change{*change}, gjallarhorn.Classify(*change, campaign, classes)
}

func (t *tracker) prune(watched map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.state {
		if _, ok := watched[k.Domain]; !ok {
			delete(t.state, k)
		}
	}
}
