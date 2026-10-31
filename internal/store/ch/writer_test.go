package ch

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
)

type fakeInserter struct {
	failEvents bool
	failStates bool

	mu    sync.Mutex
	calls []string
}

func (f *fakeInserter) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeInserter) InsertObservations(context.Context, []resolver.Observation) error {
	f.record("observations")
	return nil
}

func (f *fakeInserter) InsertChanges(context.Context, []gjallarhorn.Change) error {
	f.record("changes")
	return nil
}

func (f *fakeInserter) InsertEvents(context.Context, []gjallarhorn.Event) error {
	f.record("events")
	if f.failEvents {
		return errors.New("events unavailable")
	}
	return nil
}

func (f *fakeInserter) InsertStates(context.Context, []TupleState) error {
	f.record("states")
	if f.failStates {
		return errors.New("tuple_state unavailable")
	}
	return nil
}

func TestWriterPersistsStatesAfterEvents(t *testing.T) {
	tests := []struct {
		name       string
		failEvents bool
		failStates bool
		wantStates bool
		wantLost   bool
	}{
		{name: "states written after changes and events", wantStates: true},
		{name: "failed events hold the snapshot back", failEvents: true, wantLost: true},
		{name: "failed states are handed back", failStates: true, wantStates: true, wantLost: true},
	}
	snap := []TupleState{{Key: gjallarhorn.Key{Domain: "evil.example", QType: "A", Resolver: "9.9.9.9:53"}}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Both channels are buffered and closed before Run, so select
			// order is random: repeat to cover the snapshot arriving first.
			for range 20 {
				f := &fakeInserter{failEvents: tt.failEvents, failStates: tt.failStates}
				var lost [][]TupleState
				w := &Writer{
					store: f, size: 1000, every: time.Hour, log: slog.New(slog.DiscardHandler),
					statesLost: func(s []TupleState) { lost = append(lost, s) },
				}

				items := make(chan Item, 2)
				states := make(chan []TupleState, 1)
				items <- Item{
					Obs:     resolver.Observation{Domain: "evil.example"},
					Changes: []gjallarhorn.Change{{Key: snap[0].Key}},
					Events:  []gjallarhorn.Event{{Domain: "evil.example", Kind: gjallarhorn.KindNewRdata}},
				}
				items <- Item{Obs: resolver.Observation{Domain: "evil.example"}}
				states <- snap
				close(items)
				close(states)
				w.Run(items, states)

				first := slices.Index(f.calls, "states")
				if got := first >= 0; got != tt.wantStates {
					t.Fatalf("InsertStates called: %v, want %v (calls %v)", got, tt.wantStates, f.calls)
				}
				if first >= 0 {
					before := f.calls[:first]
					if !slices.Contains(before, "changes") || !slices.Contains(before, "events") {
						t.Fatalf("tuple_state written before changes/events: %v", f.calls)
					}
				}
				if got := len(lost) > 0; got != tt.wantLost {
					t.Fatalf("statesLost called: %v, want %v", got, tt.wantLost)
				}
				if tt.wantLost && (len(lost[0]) != 1 || lost[0][0].Key != snap[0].Key) {
					t.Fatalf("statesLost got %+v, want %+v", lost[0], snap)
				}
			}
		})
	}
}

func TestWriterEmptySnapshotWritesNothing(t *testing.T) {
	f := &fakeInserter{}
	w := &Writer{store: f, size: 1000, every: time.Hour, log: slog.New(slog.DiscardHandler)}
	items := make(chan Item)
	states := make(chan []TupleState, 1)
	states <- nil
	close(items)
	close(states)
	w.Run(items, states)
	if len(f.calls) != 0 {
		t.Fatalf("calls %v, want none", f.calls)
	}
}
