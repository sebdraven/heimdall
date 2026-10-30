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

// Writer batches items and flushes when size observations are buffered or
// every interval, whichever comes first.
type Writer struct {
	store *Store
	size  int
	every time.Duration
	log   *slog.Logger

	obs     []resolver.Observation
	changes []gjallarhorn.Change
	events  []gjallarhorn.Event
}

func (s *Store) NewWriter(size int, every time.Duration, log *slog.Logger) *Writer {
	return &Writer{
		store: s,
		size:  size,
		every: every,
		log:   log,
		obs:   make([]resolver.Observation, 0, size),
	}
}

// Run consumes in until it is closed, then flushes what remains.
func (w *Writer) Run(in <-chan Item) {
	t := time.NewTicker(w.every)
	defer t.Stop()
	for {
		select {
		case it, ok := <-in:
			if !ok {
				w.flush()
				return
			}
			w.obs = append(w.obs, it.Obs)
			w.changes = append(w.changes, it.Changes...)
			w.events = append(w.events, it.Events...)
			if len(w.obs) >= w.size {
				w.flush()
			}
		case <-t.C:
			w.flush()
		}
	}
}

func (w *Writer) flush() {
	if len(w.obs) > 0 {
		w.write("observations", len(w.obs), func(ctx context.Context) error { return w.store.InsertObservations(ctx, w.obs) })
		clear(w.obs)
		w.obs = w.obs[:0]
	}
	if len(w.changes) > 0 {
		w.write("changes", len(w.changes), func(ctx context.Context) error { return w.store.InsertChanges(ctx, w.changes) })
		w.changes = w.changes[:0]
	}
	if len(w.events) > 0 {
		w.write("events", len(w.events), func(ctx context.Context) error { return w.store.InsertEvents(ctx, w.events) })
		w.events = w.events[:0]
	}
}

func (w *Writer) write(table string, n int, fn func(context.Context) error) {
	var err error
	for attempt := 1; attempt <= flushAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
		err = fn(ctx)
		cancel()
		if err == nil {
			w.log.Debug("flushed", "table", table, "rows", n)
			return
		}
		w.log.Warn("flush failed", "table", table, "rows", n, "attempt", attempt, "err", err)
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	w.log.Error("rows dropped", "table", table, "rows", n, "err", err)
}
