package gjallarhorn

import (
	"slices"
	"time"
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

type Key struct {
	Domain   string
	QType    string
	Resolver string
}

type Observation struct {
	Key
	TS    time.Time
	Hash  uint64
	Rcode string
	Rdata []string
	TTL   uint32
}

type State struct {
	TS    time.Time
	Hash  uint64
	Rcode string
	Rdata []string
	TTL   uint32

	Ceiling  uint32
	Settled  bool
	WinStart time.Time
	WinMax   uint32
	WinN     int
}

type Change struct {
	TS time.Time
	Key
	PrevHash  uint64
	NewHash   uint64
	PrevRcode string
	NewRcode  string
	Added     []string
	Removed   []string
	PrevTTL   uint32
	NewTTL    uint32
}

// Step applies obs to the previous state of its tuple (nil for the first
// observation) and returns the new state and the change, if any. Transient
// rcodes must be filtered by the caller.
func Step(prev *State, obs Observation) (State, *Change) {
	if prev == nil {
		return initial(obs), nil
	}
	if obs.TS.Before(prev.TS) {
		return *prev, nil
	}
	if obs.Hash != prev.Hash {
		added, removed := SetDiff(prev.Rdata, obs.Rdata)
		return initial(obs), &Change{
			TS:        obs.TS,
			Key:       obs.Key,
			PrevHash:  prev.Hash,
			NewHash:   obs.Hash,
			PrevRcode: prev.Rcode,
			NewRcode:  obs.Rcode,
			Added:     added,
			Removed:   removed,
			PrevTTL:   prev.TTL,
			NewTTL:    obs.TTL,
		}
	}

	next := *prev
	next.TS, next.TTL = obs.TS, obs.TTL
	if obs.Rcode != rcodeNoError || len(obs.Rdata) == 0 {
		return next, nil
	}
	from := next.Ceiling
	next, changed := next.observeTTL(obs.TS, obs.TTL)
	if !changed {
		return next, nil
	}
	return next, &Change{
		TS:        obs.TS,
		Key:       obs.Key,
		PrevHash:  prev.Hash,
		NewHash:   obs.Hash,
		PrevRcode: prev.Rcode,
		NewRcode:  obs.Rcode,
		Added:     []string{},
		Removed:   []string{},
		PrevTTL:   from,
		NewTTL:    next.Ceiling,
	}
}

func initial(obs Observation) State {
	return State{
		TS:       obs.TS,
		Hash:     obs.Hash,
		Rcode:    obs.Rcode,
		Rdata:    obs.Rdata,
		TTL:      obs.TTL,
		Ceiling:  obs.TTL,
		WinStart: obs.TS,
		WinMax:   obs.TTL,
		WinN:     1,
	}
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
