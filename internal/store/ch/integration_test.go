//go:build integration

package ch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/resolver"
)

// testStore applies deploy/clickhouse/init.sql to a fresh, uniquely named
// database so that an existing heimdall database is never touched.
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("HEIMDALL_CH_DSN")
	if dsn == "" {
		t.Skip("HEIMDALL_CH_DSN not set")
	}
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	ctx := context.Background()
	admin, err := clickhouse.Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	db := fmt.Sprintf("heimdall_it_%d", time.Now().UnixNano())
	deploy := filepath.Join("..", "..", "..", "deploy", "clickhouse")
	// Migrations run on top of init.sql, which must already include them.
	migrations, err := filepath.Glob(filepath.Join(deploy, "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range append([]string{filepath.Join(deploy, "init.sql")}, migrations...) {
		ddl, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		script := strings.ReplaceAll(string(ddl), "heimdall.", db+".")
		script = strings.ReplaceAll(script, "IF NOT EXISTS heimdall;", "IF NOT EXISTS "+db+";")
		for _, stmt := range strings.Split(script, ";") {
			if isBlank(stmt) {
				continue
			}
			if err := admin.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s: %v\n%s", filepath.Base(file), err, stmt)
			}
		}
	}
	t.Cleanup(func() {
		_ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+db)
		_ = admin.Close()
	})

	o := *opts
	o.Auth.Database = db
	conn, err := clickhouse.Open(&o)
	if err != nil {
		t.Fatalf("open %s: %v", db, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &Store{conn: conn}
}

func isBlank(stmt string) bool {
	for line := range strings.Lines(stmt) {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "--") {
			return false
		}
	}
	return true
}

func TestAnswersFeedPDNSByOwner(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	obs := resolver.Observation{
		TS: ts, Domain: "www.x.example", QType: "A", Resolver: "9.9.9.9:53", Rcode: "NOERROR", TTL: 60,
		Rdata: []string{"192.0.2.10"},
		Answers: []resolver.Answer{
			{Name: "cdn.y.example", Type: "A", Value: "192.0.2.10"},
			{Name: "www.x.example", Type: "CNAME", Value: "cdn.y.example"},
		},
		AnswerHash: resolver.AnswerHash("NOERROR", []string{"192.0.2.10"}),
		Wire:       []byte{0x12, 0x34},
	}
	if err := s.InsertObservations(ctx, []resolver.Observation{obs}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rows, err := s.conn.Query(ctx, `
		SELECT tupleElement(a, 'name'), tupleElement(a, 'type'), tupleElement(a, 'value')
		FROM observations ARRAY JOIN answers AS a
		WHERE domain = ?
		ORDER BY 1, 2, 3`, obs.Domain)
	if err != nil {
		t.Fatal(err)
	}
	var got []resolver.Answer
	for rows.Next() {
		var a resolver.Answer
		if err := rows.Scan(&a.Name, &a.Type, &a.Value); err != nil {
			t.Fatal(err)
		}
		got = append(got, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, obs.Answers) {
		t.Fatalf("observations.answers = %+v, want %+v", got, obs.Answers)
	}

	for _, want := range obs.Answers {
		recs, err := s.PDNSByName(ctx, want.Name, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != 1 {
			t.Fatalf("pdns %s: %d records, want 1: %+v", want.Name, len(recs), recs)
		}
		r := recs[0]
		if r.RRType != want.Type || r.RData != want.Value || r.Count != 1 || !r.FirstSeen.Equal(ts) || !r.LastSeen.Equal(ts) {
			t.Errorf("pdns %s = %+v, want %s %s seen once at %s", want.Name, r, want.Type, want.Value, ts)
		}
	}
}

func TestAuthorityFeedsPDNSByZone(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	soa := "ns1.syamcloud.com hostmaster.syamcloud.com 2026103101 7200 3600 1209600 300"
	obs := resolver.Observation{
		TS: ts, Domain: "proxy.syamcloud.com", QType: "SOA", Resolver: "9.9.9.9:53", Rcode: "NOERROR",
		Rdata: []string{}, Answers: []resolver.Answer{},
		Authority: []resolver.Answer{
			{Name: "syamcloud.com", Type: "NS", Value: "ns1.example.net"},
			{Name: "syamcloud.com", Type: "SOA", Value: soa},
		},
		Zone:       "syamcloud.com",
		AnswerHash: resolver.AnswerHash("NOERROR", nil),
	}
	nx := obs
	nx.TS, nx.Domain, nx.Rcode = ts.Add(time.Minute), "gone.syamcloud.com", "NXDOMAIN"
	if err := s.InsertObservations(ctx, []resolver.Observation{obs, nx}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	recs, err := s.PDNSByName(ctx, "syamcloud.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []resolver.Answer
	for _, r := range recs {
		got = append(got, resolver.Answer{Name: r.RRName, Type: r.RRType, Value: r.RData})
		if r.Count != 1 || !r.FirstSeen.Equal(ts) || !r.LastSeen.Equal(ts) {
			t.Errorf("pdns %+v: want seen once at %s, NXDOMAIN ignored", r, ts)
		}
	}
	slices.SortFunc(got, func(a, b resolver.Answer) int { return strings.Compare(a.Type, b.Type) })
	if !slices.Equal(got, obs.Authority) {
		t.Fatalf("pdns syamcloud.com = %+v, want %+v", got, obs.Authority)
	}
	if recs, err := s.PDNSByName(ctx, obs.Domain, 10); err != nil || len(recs) != 0 {
		t.Fatalf("pdns %s = %+v, %v; want nothing", obs.Domain, recs, err)
	}
}

func TestSearchNamesAndValues(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	answer := func(name, typ, value string) resolver.Observation {
		return resolver.Observation{
			TS: ts, Domain: name, QType: typ, Resolver: "9.9.9.9:53", Rcode: "NOERROR", Rdata: []string{value},
			Answers: []resolver.Answer{{Name: name, Type: typ, Value: value}},
		}
	}
	if err := s.InsertObservations(ctx, []resolver.Observation{
		answer("node_1.otax.fun", "A", "192.0.2.1"),
		answer("node_1.otax.fun", "AAAA", "2001:db8::1"),
		answer("nodex1.otax.fun", "A", "192.0.2.1"),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	names, err := s.SearchNames(ctx, `%NODE\_1%`, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].RRName != "node_1.otax.fun" || !slices.Equal(names[0].RRTypes, []string{"A", "AAAA"}) || names[0].Count != 2 {
		t.Fatalf("names = %+v, want node_1.otax.fun only, A and AAAA, count 2", names)
	}
	values, err := s.SearchValues(ctx, `192.0.2.%`, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].RData != "192.0.2.1" || values[0].RRType != "A" || values[0].Names != 2 {
		t.Fatalf("values = %+v, want 192.0.2.1 A held by 2 names", values)
	}
}

func TestStatesRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	want := []TupleState{
		{
			Key: gjallarhorn.Key{Domain: "rt.example", QType: "A", Resolver: "9.9.9.9:53"},
			State: gjallarhorn.State{
				TS:       time.Date(2026, 3, 1, 12, 0, 0, 123_000_000, time.UTC),
				Rcode:    "NOERROR",
				Tracked:  []string{"192.0.2.1", "192.0.2.2"},
				Missing:  []uint32{0, 2},
				Hash:     0xdeadbeefcafef00d,
				TTL:      120,
				Ceiling:  300,
				Settled:  true,
				WinStart: time.Date(2026, 3, 1, 11, 55, 0, 456_000_000, time.UTC),
				WinMax:   280,
				WinN:     5,
			},
		},
		{
			Key: gjallarhorn.Key{Domain: "rt.example", QType: "MX", Resolver: "1.1.1.1:53"},
			State: gjallarhorn.State{
				TS:       time.Date(2026, 3, 1, 12, 0, 1, 0, time.UTC),
				Rcode:    "NXDOMAIN",
				Tracked:  []string{},
				Missing:  []uint32{},
				Hash:     42,
				WinStart: time.Date(2026, 3, 1, 12, 0, 1, 0, time.UTC),
				WinN:     1,
			},
		},
	}
	if err := s.InsertStates(ctx, want); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got := loadByKey(t, s)
	if len(got) != len(want) {
		t.Fatalf("loaded %d states, want %d", len(got), len(want))
	}
	for _, w := range want {
		g, ok := got[w.Key]
		if !ok {
			t.Fatalf("state %+v not loaded", w.Key)
		}
		if !sameState(g, w.State) {
			t.Errorf("%+v:\n got  %+v\n want %+v", w.Key, g, w.State)
		}
	}
}

func TestStatesFinalKeepsLatest(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	older := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Minute)
	state := func(key gjallarhorn.Key, ts time.Time, hash uint64) TupleState {
		return TupleState{Key: key, State: gjallarhorn.State{
			TS: ts, Rcode: "NOERROR", Tracked: []string{"192.0.2.1"}, Missing: []uint32{0}, Hash: hash, WinStart: ts,
		}}
	}
	inOrder := gjallarhorn.Key{Domain: "final.example", QType: "A", Resolver: "9.9.9.9:53"}
	reversed := gjallarhorn.Key{Domain: "final.example", QType: "AAAA", Resolver: "9.9.9.9:53"}
	for _, batch := range [][]TupleState{
		{state(inOrder, older, 1), state(reversed, newer, 2)},
		{state(inOrder, newer, 2), state(reversed, older, 1)},
	} {
		if err := s.InsertStates(ctx, batch); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got := loadByKey(t, s)
	if len(got) != 2 {
		t.Fatalf("FINAL returned %d rows, want 2", len(got))
	}
	for _, k := range []gjallarhorn.Key{inOrder, reversed} {
		if g := got[k]; !g.TS.Equal(newer) || g.Hash != 2 {
			t.Errorf("%+v: kept ts %s hash %d, want the latest row", k, g.TS, g.Hash)
		}
	}
}

func loadByKey(t *testing.T, s *Store) map[gjallarhorn.Key]gjallarhorn.State {
	t.Helper()
	rows, err := s.LoadStates(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out := make(map[gjallarhorn.Key]gjallarhorn.State, len(rows))
	for _, r := range rows {
		if _, dup := out[r.Key]; dup {
			t.Fatalf("duplicate state for %+v", r.Key)
		}
		out[r.Key] = r.State
	}
	return out
}

func sameState(a, b gjallarhorn.State) bool {
	return a.TS.Equal(b.TS) && a.Rcode == b.Rcode &&
		slices.Equal(a.Tracked, b.Tracked) && slices.Equal(a.Missing, b.Missing) &&
		a.Hash == b.Hash && a.TTL == b.TTL && a.Ceiling == b.Ceiling && a.Settled == b.Settled &&
		a.WinStart.Equal(b.WinStart) && a.WinMax == b.WinMax && a.WinN == b.WinN
}
