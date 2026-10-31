package gjallarhorn

import (
	"maps"
	"slices"
	"time"

	"github.com/sebdraven/heimdall/internal/resolver"
)

const (
	rcodeNoError  = "NOERROR"
	rcodeNXDomain = "NXDOMAIN"
)

// TTL tracking: a recursive resolver returns a countdown bounded by the
// authoritative TTL, so the ceiling is learnt as the max observed value.
// A raise is reported when a value exceeds TTLRaiseFactor × ceiling; a drop
// when a full window (≥ ceiling seconds and ≥ TTLWindowSamples samples)
// never reached ceiling / TTLDropFactor.
const (
	TTLWindowSamples = 8
	TTLRaiseFactor   = 2
	TTLDropFactor    = 4
)

var TransientRcodes = []string{"TIMEOUT", "NETERR", "SERVFAIL", "REFUSED"}

// Transient rcodes are stored as observations but never update the
// change-detection state.
func Transient(rcode string) bool {
	return slices.Contains(TransientRcodes, rcode)
}

// Resolvers often serve a rotating subset of a larger pool for these types,
// so a value is only removed after RemovalGrace consecutive absences.
var multiValued = map[string]bool{"A": true, "AAAA": true, "NS": true, "MX": true, "TXT": true}

type Key struct {
	Domain   string
	QType    string
	Resolver string
}

type Observation struct {
	Key
	TS    time.Time
	Rcode string
	Rdata []string
	TTL   uint32
}

// State is the detection state of one tuple. Tracked is the sorted set of
// values considered present, Missing[i] the consecutive absences of
// Tracked[i], and Hash covers (Rcode, Tracked).
type State struct {
	TS      time.Time
	Rcode   string
	Tracked []string
	Missing []uint32
	Hash    uint64
	TTL     uint32

	Ceiling  uint32
	Settled  bool
	WinStart time.Time
	WinMax   uint32
	WinN     uint32
}

type Change struct {
	TS time.Time
	Key
	// Hashes of (rcode, tracked set) before and after, not of the raw
	// answer: they never match observations.answer_hash.
	PrevTrackedHash uint64
	NewTrackedHash  uint64
	PrevRcode       string
	NewRcode        string
	Added           []string
	Removed         []string
	PrevTTL         uint32
	NewTTL          uint32
}

// Step applies obs to the previous state of its tuple (nil for the first
// observation) and returns the new state and the change of the tracked set,
// if any. Transient rcodes must be filtered by the caller.
func Step(prev *State, obs Observation, grace int) (State, *Change) {
	if prev == nil {
		return initial(obs, observedSet(obs), nil), nil
	}
	if obs.TS.Before(prev.TS) {
		return *prev, nil
	}

	tracked, missing := nextSet(*prev, obs, grace)
	if hash := resolver.AnswerHash(obs.Rcode, tracked); hash != prev.Hash {
		added, removed := SetDiff(prev.Tracked, tracked)
		next := initial(obs, tracked, missing)
		return next, &Change{
			TS:              obs.TS,
			Key:             obs.Key,
			PrevTrackedHash: prev.Hash,
			NewTrackedHash:  next.Hash,
			PrevRcode:       prev.Rcode,
			NewRcode:        obs.Rcode,
			Added:           added,
			Removed:         removed,
			PrevTTL:         prev.TTL,
			NewTTL:          obs.TTL,
		}
	}

	next := *prev
	next.TS, next.TTL, next.Missing = obs.TS, obs.TTL, missing
	if obs.Rcode != rcodeNoError || len(obs.Rdata) == 0 {
		return next, nil
	}
	from := next.Ceiling
	next, changed := next.observeTTL(obs.TS, obs.TTL)
	if !changed {
		return next, nil
	}
	return next, &Change{
		TS:              obs.TS,
		Key:             obs.Key,
		PrevTrackedHash: prev.Hash,
		NewTrackedHash:  prev.Hash,
		PrevRcode:       prev.Rcode,
		NewRcode:        obs.Rcode,
		Added:           []string{},
		Removed:         []string{},
		PrevTTL:         from,
		NewTTL:          next.Ceiling,
	}
}

func initial(obs Observation, tracked []string, missing []uint32) State {
	if missing == nil {
		missing = make([]uint32, len(tracked))
	}
	return State{
		TS:       obs.TS,
		Rcode:    obs.Rcode,
		Tracked:  tracked,
		Missing:  missing,
		Hash:     resolver.AnswerHash(obs.Rcode, tracked),
		TTL:      obs.TTL,
		Ceiling:  obs.TTL,
		WinStart: obs.TS,
		WinMax:   obs.TTL,
		WinN:     1,
	}
}

func observedSet(obs Observation) []string {
	if obs.Rcode != rcodeNoError {
		return []string{}
	}
	out := slices.Clone(obs.Rdata)
	slices.Sort(out)
	return slices.Compact(out)
}

// nextSet applies hysteresis only between two NOERROR answers of a
// multi-valued type; rcode transitions and single-valued types replace the
// set at once.
func nextSet(prev State, obs Observation, grace int) ([]string, []uint32) {
	cur := observedSet(obs)
	if obs.Rcode != rcodeNoError || prev.Rcode != rcodeNoError || !multiValued[obs.QType] {
		return cur, make([]uint32, len(cur))
	}
	return Track(prev.Tracked, prev.Missing, cur, grace)
}

// Track adds new values at once and drops a tracked value once it has been
// missing from grace consecutive observations.
func Track(tracked []string, missing []uint32, observed []string, grace int) ([]string, []uint32) {
	grace = max(grace, 1)
	seen := make(map[string]struct{}, len(observed))
	for _, v := range observed {
		seen[v] = struct{}{}
	}
	miss := make(map[string]uint32, len(tracked)+len(observed))
	for i, v := range tracked {
		if _, ok := seen[v]; ok {
			miss[v] = 0
			continue
		}
		var m uint32
		if i < len(missing) {
			m = missing[i]
		}
		if m++; int(m) < grace {
			miss[v] = m
		}
	}
	for _, v := range observed {
		miss[v] = 0
	}
	out := slices.Sorted(maps.Keys(miss))
	counts := make([]uint32, len(out))
	for i, v := range out {
		counts[i] = miss[v]
	}
	return out, counts
}

func (s State) observeTTL(ts time.Time, ttl uint32) (State, bool) {
	if s.Settled && uint64(ttl) > TTLRaiseFactor*uint64(s.Ceiling) {
		s.Ceiling = ttl
		s.WinStart, s.WinMax, s.WinN = ts, ttl, 1
		return s, true
	}
	s.Ceiling = max(s.Ceiling, ttl)
	s.WinMax = max(s.WinMax, ttl)
	s.WinN++
	if s.WinN < TTLWindowSamples || ts.Sub(s.WinStart) < time.Duration(s.Ceiling)*time.Second {
		return s, false
	}
	changed := s.Settled && TTLDropFactor*uint64(s.WinMax) < uint64(s.Ceiling)
	if changed {
		s.Ceiling = s.WinMax
	}
	s.Settled = true
	s.WinStart, s.WinMax, s.WinN = ts, 0, 0
	return s, changed
}

// SetDiff returns the sorted values present only in cur (added) and only in
// prev (removed).
func SetDiff(prev, cur []string) (added, removed []string) {
	in := func(set []string) map[string]struct{} {
		m := make(map[string]struct{}, len(set))
		for _, v := range set {
			m[v] = struct{}{}
		}
		return m
	}
	p, c := in(prev), in(cur)
	added, removed = []string{}, []string{}
	for v := range c {
		if _, ok := p[v]; !ok {
			added = append(added, v)
		}
	}
	for v := range p {
		if _, ok := c[v]; !ok {
			removed = append(removed, v)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}
