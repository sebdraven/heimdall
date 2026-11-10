package correlate

import (
	"cmp"
	"slices"
	"time"
)

// Pair is what links two campaigns, A < B. Counts are the distinct values
// of each kind they share. FirstSeen is the first sighting of their oldest
// link, LastSeen the last sighting of any.
type Pair struct {
	A         int64
	B         int64
	Score     float64
	Counts    map[string]int
	FirstSeen time.Time
	LastSeen  time.Time
}

type valueKey struct{ kind, value string }

// Score is 1 − Π(1 − w) over the distinct values (kind, value) of ev, each
// with the highest weight of its links, at most 1.
func Score(ev []Evidence) float64 {
	best := map[valueKey]float64{}
	for _, e := range ev {
		k := valueKey{e.Kind, e.Value}
		best[k] = max(best[k], e.Weight)
	}
	rest := 1.0
	for _, w := range best {
		rest *= 1 - min(max(w, 0), 1)
	}
	return round(min(1, 1-rest))
}

// CampaignPair returns the campaigns of e, lower id first.
func CampaignPair(e Evidence) (int64, int64) {
	return min(e.CampaignA, e.CampaignB), max(e.CampaignA, e.CampaignB)
}

// Pairs groups ev by pair of campaigns, highest score first.
func Pairs(ev []Evidence) []Pair {
	type pk struct{ a, b int64 }
	groups := map[pk][]Evidence{}
	for _, e := range ev {
		a, b := CampaignPair(e)
		groups[pk{a, b}] = append(groups[pk{a, b}], e)
	}
	out := make([]Pair, 0, len(groups))
	for k, list := range groups {
		p := Pair{A: k.a, B: k.b, Score: Score(list), Counts: map[string]int{}}
		values := map[valueKey]bool{}
		for _, e := range list {
			if !values[valueKey{e.Kind, e.Value}] {
				values[valueKey{e.Kind, e.Value}] = true
				p.Counts[e.Kind]++
			}
			if !e.FirstSeen.IsZero() && (p.FirstSeen.IsZero() || e.FirstSeen.Before(p.FirstSeen)) {
				p.FirstSeen = e.FirstSeen
			}
			if e.LastSeen.After(p.LastSeen) {
				p.LastSeen = e.LastSeen
			}
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(x, y Pair) int {
		return cmp.Or(cmp.Compare(y.Score, x.Score), cmp.Compare(x.A, y.A), cmp.Compare(x.B, y.B))
	})
	return out
}

// Between returns the links of ev between campaigns a and b, in either
// order.
func Between(ev []Evidence, a, b int64) []Evidence {
	var out []Evidence
	for _, e := range ev {
		if (e.CampaignA == a && e.CampaignB == b) || (e.CampaignA == b && e.CampaignB == a) {
			out = append(out, e)
		}
	}
	return out
}

// OfKinds keeps the links of the given kinds, all of them when kinds is
// empty.
func OfKinds(ev []Evidence, kinds []string) []Evidence {
	if len(kinds) == 0 {
		return ev
	}
	var out []Evidence
	for _, e := range ev {
		if slices.Contains(kinds, e.Kind) {
			out = append(out, e)
		}
	}
	return out
}

// SortByWeight sorts ev by weight, then latest first sighting, then key.
func SortByWeight(ev []Evidence) {
	slices.SortFunc(ev, func(a, b Evidence) int {
		return cmp.Or(cmp.Compare(b.Weight, a.Weight), b.FirstSeen.Compare(a.FirstSeen), compareKey(a, b))
	})
}
