package ch

import (
	"context"
	"log/slog"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
)

const (
	flushTimeout  = 30 * time.Second
	flushAttempts = 3
)

type Item struct {
	Obs     resolver.Observation
	Changes []gjallarhorn.Change
	Events  []gjallarhorn.Event
}

type TupleState struct {
	Key   gjallarhorn.Key
	State gjallarhorn.State
}

// inserter is the subset of Store used by Writer, replaced in tests.
type inserter interface {
	InsertObservations(context.Context, []resolver.Observation) error
	InsertChanges(context.Context, []gjallarhorn.Change) error
	InsertEvents(context.Context, []gjallarhorn.Event) error
	InsertStates(context.Context, []TupleState) error
}

// Writer batches items and flushes when size observations are buffered or
// every interval, whichever comes first.
// A state is persisted only after its changes/events, so a crash can at worst duplicate an event, never lose one.
type Writer struct {
	store   inserter
	size    int
	every   time.Duration
	backoff time.Duration
	log     *slog.Logger

	// statesLost receives a snapshot whose insertion failed, so that its
	// tuples can be resent with the next one.
	statesLost func([]TupleState)

	obs     []resolver.Observation
	changes []gjallarhorn.Change
	events  []gjallarhorn.Event
}

func (s *Store) NewWriter(size int, every time.Duration, log *slog.Logger, statesLost func([]TupleState)) *Writer {
	return &Writer{
		store:      s,
		size:       size,
		every:      every,
		backoff:    time.Second,
		log:        log,
		statesLost: statesLost,
		obs:        make([]resolver.Observation, 0, size),
	}
}

// Run consumes items and state snapshots until both channels are closed,
// then flushes what remains.
func (w *Writer) Run(items <-chan Item, states <-chan []TupleState) {
	t := time.NewTicker(w.every)
	defer t.Stop()
	for items != nil || states != nil {
		select {
		case it, ok := <-items:
			if !ok {
				items = nil
				continue
			}
			w.add(it)
			if len(w.obs) >= w.size {
				w.flush()
			}
		case snap, ok := <-states:
			if !ok {
				states = nil
				continue
			}
			items = w.drain(items)
			w.persist(snap)
		case <-t.C:
			w.flush()
		}
	}
	w.flush()
}

func (w *Writer) add(it Item) {
	w.obs = append(w.obs, it.Obs)
	w.changes = append(w.changes, it.Changes...)
	w.events = append(w.events, it.Events...)
}

// drain takes the items already queued, which may predate the snapshot
// being handled. It returns nil once items is closed.
func (w *Writer) drain(items <-chan Item) <-chan Item {
	for items != nil {
		select {
		case it, ok := <-items:
			if !ok {
				return nil
			}
			w.add(it)
		default:
			return items
		}
	}
	return nil
}

// persist writes snap only if every buffered change and event was stored
// first; otherwise, or if the insert fails, snap goes back to statesLost.
func (w *Writer) persist(snap []TupleState) {
	if len(snap) == 0 {
		return
	}
	if !w.flush() {
		w.lose(snap)
		return
	}
	if err := w.write("tuple_state", len(snap), flushAttempts, func(ctx context.Context) error { return w.store.InsertStates(ctx, snap) }); err != nil {
		w.lose(snap)
	}
}

func (w *Writer) lose(snap []TupleState) {
	if w.statesLost != nil {
		w.statesLost(snap)
	}
}

// flush reports whether changes and events are all stored. Failed changes
// and events stay buffered for the next flush; failed observations are
// dropped and never hold states back.
func (w *Writer) flush() bool {
	if len(w.obs) > 0 {
		_ = w.write("observations", len(w.obs), flushAttempts, func(ctx context.Context) error { return w.store.InsertObservations(ctx, w.obs) })
		clear(w.obs)
		w.obs = w.obs[:0]
	}
	ok := true
	if len(w.changes) > 0 {
		if w.write("changes", len(w.changes), flushAttempts, func(ctx context.Context) error { return w.store.InsertChanges(ctx, w.changes) }) == nil {
			w.changes = w.changes[:0]
		} else {
			ok = false
		}
	}
	if len(w.events) > 0 {
		if w.write("events", len(w.events), flushAttempts, func(ctx context.Context) error { return w.store.InsertEvents(ctx, w.events) }) == nil {
			w.events = w.events[:0]
		} else {
			ok = false
		}
	}
	return ok
}

func (w *Writer) write(table string, n, attempts int, fn func(context.Context) error) error {
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		err = fn(ctx)
		cancel()
		if err == nil {
			w.log.Debug("flushed", "table", table, "rows", n)
			return nil
		}
		w.log.Warn("flush failed", "table", table, "rows", n, "attempt", attempt, "err", err)
		if attempt < attempts {
			time.Sleep(time.Duration(attempt) * w.backoff)
		}
	}
	w.log.Error("rows not written", "table", table, "rows", n, "err", err)
	return err
}
