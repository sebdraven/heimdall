package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/sebdraven/heimdall/internal/cdn"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

// cdnSyncStore is what cdn-sync writes to; *pg.Store is one.
type cdnSyncStore interface {
	SyncCDNPrefixes(ctx context.Context, provider, source string, prefixes []netip.Prefix, dryRun bool) (pg.CDNSync, error)
	Audit(ctx context.Context, userID *int64, action, target string) error
}

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func cdnSyncCommand(ctx context.Context, s *pg.Store, fs *flag.FlagSet, args []string) error {
	return cdnSync(ctx, s, cdn.NewSyncClient(), cdn.Sources, cdn.ASNSource, fs, args, os.Stdout, os.Stderr)
}

// cdnSync syncs each provider in its own transaction; one that fails does
// not stop the others but makes the command fail.
func cdnSync(ctx context.Context, st cdnSyncStore, client *http.Client, catalog []cdn.Source, asnSource func(uint32, string) cdn.Source,
	fs *flag.FlagSet, args []string, stdout, stderr io.Writer) error {
	var providers, asns, asProviders stringList
	fs.Var(&providers, "provider", "provider to sync, repeatable: "+sourceNames(catalog)+" (default all)")
	fs.Var(&asns, "asn", "AS whose announced prefixes are synced from RIPEstat, repeatable, each with -as-provider")
	fs.Var(&asProviders, "as-provider", "provider name of the -asn of the same rank")
	dryRun := fs.Bool("dry-run", false, "count the changes without writing anything")
	if err := parse(fs, args); err != nil {
		return err
	}
	sources, err := syncSources(catalog, asnSource, providers, asns, asProviders)
	if err != nil {
		return err
	}
	for _, src := range sources[len(sources)-len(asns):] {
		fmt.Fprintf(stderr, "warning: %s: every prefix announced by the AS is marked CDN, including any non-CDN hosting it announces\n", src.Name)
	}
	failed := 0
	for _, src := range sources {
		if err := syncSource(ctx, st, client, src, *dryRun, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "error: %s: %v\n", src.Name, err)
			failed++
		}
	}
	if *dryRun {
		fmt.Fprintln(stdout, "dry run: nothing written")
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d provider(s) failed", failed, len(sources))
	}
	return nil
}

func syncSource(ctx context.Context, st cdnSyncStore, client *http.Client, src cdn.Source, dryRun bool, stdout, stderr io.Writer) error {
	prefixes, err := cdn.Fetch(ctx, client, src)
	if err != nil {
		return err
	}
	res, err := st.SyncCDNPrefixes(ctx, src.Provider, "sync:"+src.Name, prefixes, dryRun)
	if err != nil {
		return err
	}
	line := fmt.Sprintf("%s: %d added, %d removed, %d unchanged", src.Name, res.Added, res.Removed, res.Unchanged)
	if res.Skipped > 0 {
		line += fmt.Sprintf(", %d already listed by another source", res.Skipped)
	}
	fmt.Fprintln(stdout, line)
	if !dryRun && res.Added+res.Removed > 0 {
		target := fmt.Sprintf("%s (%d added, %d removed)", src.Provider, res.Added, res.Removed)
		if err := st.Audit(ctx, nil, "cli:cdnprefix.sync", target); err != nil {
			fmt.Fprintln(stderr, "warning: audit log:", err)
		}
	}
	return nil
}

// syncSources returns the providers asked for, all of catalog without
// -provider, then one source per -asn. An -as-provider may not reuse the
// name of a built-in provider, whose "sync:<name>" prefixes it would replace.
func syncSources(catalog []cdn.Source, asnSource func(uint32, string) cdn.Source, providers, asns, asProviders []string) ([]cdn.Source, error) {
	var out []cdn.Source
	seen := map[string]bool{}
	for _, p := range providers {
		name := strings.ToLower(strings.TrimSpace(p))
		i := slices.IndexFunc(catalog, func(s cdn.Source) bool { return s.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("%w: unknown provider %q (known: %s)", errUsage, p, sourceNames(catalog))
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, catalog[i])
		}
	}
	if len(providers) == 0 {
		out = slices.Clone(catalog)
	}
	if len(asns) != len(asProviders) {
		return nil, fmt.Errorf("%w: each -asn needs its -as-provider", errUsage)
	}
	named := map[string]bool{}
	for i, v := range asns {
		asn, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v)), "AS"), 10, 32)
		if err != nil || asn == 0 {
			return nil, fmt.Errorf("%w: invalid ASN %q", errUsage, v)
		}
		provider := strings.TrimSpace(asProviders[i])
		name := strings.ToLower(provider)
		switch {
		case provider == "":
			return nil, fmt.Errorf("%w: -as-provider is empty", errUsage)
		case slices.ContainsFunc(catalog, func(s cdn.Source) bool { return s.Name == name }):
			return nil, fmt.Errorf("%w: -as-provider %q is a built-in provider, use another name", errUsage, provider)
		case named[name]:
			return nil, fmt.Errorf("%w: -as-provider %q given twice", errUsage, provider)
		}
		named[name] = true
		out = append(out, asnSource(uint32(asn), provider))
	}
	return out, nil
}

func sourceNames(catalog []cdn.Source) string {
	names := make([]string, 0, len(catalog))
	for _, s := range catalog {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}
