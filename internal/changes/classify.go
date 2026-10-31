package gjallarhorn

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
)

const (
	KindNewRdata        = "new_rdata"
	KindRemovedRdata    = "removed_rdata"
	KindNXDomain        = "nxdomain"
	KindResurrection    = "resurrection"
	KindNSSinkhole      = "ns_sinkhole"
	KindNSParking       = "ns_parking"
	KindSOASerialChange = "soa_serial_change"
	KindTTLChange       = "ttl_change"
)

var Kinds = []string{
	KindNewRdata, KindRemovedRdata, KindNXDomain, KindResurrection,
	KindNSSinkhole, KindNSParking, KindSOASerialChange, KindTTLChange,
}

const (
	NSKindSinkhole = "sinkhole"
	NSKindParking  = "parking"
)

// Name-level transitions are reported once per resolver, on this qtype only.
const nameLevelQType = "A"

type Event struct {
	TS       time.Time
	Domain   string
	Campaign string
	Kind     string
	QType    string
	Resolver string
	Detail   string
}

type NSClass struct {
	Pattern string
	Kind    string
	Label   string
}

func Classify(ch Change, campaign string, classes []NSClass) []Event {
	evs := []Event{}
	emit := func(kind string, detail map[string]any) {
		b, _ := json.Marshal(detail)
		evs = append(evs, Event{
			TS:       ch.TS,
			Domain:   ch.Domain,
			Campaign: campaign,
			Kind:     kind,
			QType:    ch.QType,
			Resolver: ch.Resolver,
			Detail:   string(b),
		})
	}

	if ch.PrevTrackedHash == ch.NewTrackedHash {
		if ch.PrevTTL != ch.NewTTL {
			emit(KindTTLChange, map[string]any{"prev_ttl": ch.PrevTTL, "new_ttl": ch.NewTTL})
		}
		return evs
	}

	prevOK, newOK := ch.PrevRcode == rcodeNoError, ch.NewRcode == rcodeNoError
	if ch.QType == nameLevelQType {
		switch {
		case prevOK && ch.NewRcode == rcodeNXDomain:
			emit(KindNXDomain, map[string]any{"prev_rdata": ch.Removed})
		case ch.PrevRcode == rcodeNXDomain && newOK:
			emit(KindResurrection, map[string]any{"rdata": ch.Added})
		}
	}
	if !newOK {
		return evs
	}

	if prevOK {
		rdataChanged := true
		if ch.QType == "SOA" {
			prevSerial, newSerial, serialChanged, otherChanged := soaDelta(ch.Removed, ch.Added)
			if serialChanged {
				emit(KindSOASerialChange, map[string]any{"prev_serial": prevSerial, "new_serial": newSerial})
			}
			rdataChanged = otherChanged
		}
		if rdataChanged && len(ch.Added) > 0 {
			emit(KindNewRdata, map[string]any{"values": ch.Added})
		}
		if rdataChanged && len(ch.Removed) > 0 {
			emit(KindRemovedRdata, map[string]any{"values": ch.Removed})
		}
	}

	if ch.QType == "NS" {
		matches := map[string][]map[string]string{}
		for _, ns := range ch.Added {
			if c, ok := MatchNS(ns, classes); ok {
				matches[c.Kind] = append(matches[c.Kind], map[string]string{"ns": ns, "pattern": c.Pattern, "label": c.Label})
			}
		}
		if m := matches[NSKindSinkhole]; len(m) > 0 {
			emit(KindNSSinkhole, map[string]any{"matches": m})
		}
		if m := matches[NSKindParking]; len(m) > 0 {
			emit(KindNSParking, map[string]any{"matches": m})
		}
	}
	return evs
}

// MatchNS reports the first class whose pattern is ns itself or a parent
// domain of ns.
func MatchNS(ns string, classes []NSClass) (NSClass, bool) {
	for _, c := range classes {
		p := NormalizePattern(c.Pattern)
		if p == "" {
			continue
		}
		if ns == p || strings.HasSuffix(ns, "."+p) {
			return c, true
		}
	}
	return NSClass{}, false
}

func NormalizePattern(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	p = strings.TrimPrefix(p, "*.")
	return strings.Trim(p, ".")
}

// soaDelta compares single SOA rdata values in presentation form
// "mname rname serial refresh retry expire minimum".
func soaDelta(removed, added []string) (prevSerial, newSerial string, serialChanged, otherChanged bool) {
	if len(removed) != 1 || len(added) != 1 {
		return "", "", false, true
	}
	a, b := strings.Fields(removed[0]), strings.Fields(added[0])
	if len(a) != 7 || len(b) != 7 {
		return "", "", false, true
	}
	prevSerial, newSerial = a[2], b[2]
	a[2], b[2] = "", ""
	return prevSerial, newSerial, prevSerial != newSerial, !slices.Equal(a, b)
}
