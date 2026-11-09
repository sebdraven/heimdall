package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/store/ch"
)

// maxNSSet caps the nameservers of an NS set graph.
const maxNSSet = 16

// parseNSSet returns the comma-separated nameservers of v normalized, sorted
// and unique, between ch.MinNSSet and maxNSSet of them.
func parseNSSet(v string) ([]string, bool) {
	var ns []string
	for _, p := range strings.Split(v, ",") {
		n, err := resolver.NormalizeFQDN(p)
		if err != nil {
			return nil, false
		}
		ns = append(ns, n)
	}
	ns = slices.Compact(slices.Sorted(slices.Values(ns)))
	return ns, len(ns) >= ch.MinNSSet && len(ns) <= maxNSSet
}

// nssetRootNode is the node of an NS set graph, which has no page.
func nssetRootNode(ns []string) graphNode {
	n := nssetNode(&ch.NSSet{NS: ns})
	n.Href = ""
	return n
}

// loadNSGraph reads the graph of an NS set: the set and the names whose
// current NS set equals it.
func (s *server) loadNSGraph(ctx context.Context, ns []string) (graphJSON, error) {
	matches, err := s.graph.NSPairPivots(ctx, "", ns, graphMaxNodes)
	if err != nil {
		return graphJSON{}, fmt.Errorf("ns pair pivots: %w", err)
	}
	in := graphInput{NS: ns, NSPeers: map[string][]ch.NSPairPivot{nssetID(ns): matches}, Partial: len(matches) == graphMaxNodes}
	return s.watchGraph(ctx, buildGraph(in, s.cdn, graphMaxNodes))
}

// apiGraphNS serves /api/graph/ns/{set} and /graph/ns/{set}/data, {set}
// being the nameservers separated by commas.
func (s *server) apiGraphNS(w http.ResponseWriter, r *http.Request) {
	ns, ok := parseNSSet(r.PathValue("set"))
	if !ok {
		apiError(w, http.StatusBadRequest, "invalid NS set")
		return
	}
	g, err := s.loadNSGraph(r.Context(), ns)
	if err != nil {
		s.apiStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, g)
}
