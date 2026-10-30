package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	gjallarhorn "github.com/sebdraven/heimdall/internal/changes"
	"github.com/sebdraven/heimdall/internal/config"
	"github.com/sebdraven/heimdall/internal/resolver"
	"github.com/sebdraven/heimdall/internal/scheduler"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

const stateWindow = 30 * 24 * time.Hour

func main() {
	if err := run(); err != nil {
		slog.Error("heimdall-collector failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := cfg.Logger("collector")
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	var pgs *pg.Store
	if err := retry(ctx, log, "postgres", func() (err error) {
		pgs, err = pg.Open(ctx, cfg.PGDSN)
		return err
	}); err != nil {
		return err
	}
	defer pgs.Close()

	var chs *ch.Store
	if err := retry(ctx, log, "clickhouse", func() (err error) {
		chs, err = ch.Open(ctx, ch.Options{Addr: cfg.CHAddr, Database: cfg.CHDatabase, User: cfg.CHUser, Password: cfg.CHPassword})
		return err
	}); err != nil {
		return err
	}
	defer chs.Close()

	tr := newTracker()
	if err := retry(ctx, log, "state", func() error { return tr.load(ctx, chs, log) }); err != nil {
		return err
	}

	jobs := make(chan scheduler.Job, cfg.Workers*4)
	items := make(chan ch.Item, cfg.BatchSize)
	sched := scheduler.New(resolver.QTypes, jobs)
	limits := &limiters{m: map[string]*rate.Limiter{}}
	var classes atomic.Pointer[[]gjallarhorn.NSClass]

	reload := func() error {
		domains, err := pgs.EnabledDomains(ctx)
		if err != nil {
			return err
		}
		resolvers, err := pgs.Resolvers(ctx)
		if err != nil {
			return err
		}
		nsc, err := pgs.NSClasses(ctx)
		if err != nil {
			return err
		}

		sd := make([]scheduler.Domain, 0, len(domains))
		watched := make(map[string]struct{}, len(domains))
		for _, d := range domains {
			sd = append(sd, scheduler.Domain{FQDN: d.FQDN, Campaign: d.Campaign, Interval: time.Duration(d.IntervalSeconds) * time.Second})
			watched[d.FQDN] = struct{}{}
		}
		var enabled []pg.Resolver
		var addrs []string
		for _, r := range resolvers {
			if r.Enabled {
				enabled = append(enabled, r)
				addrs = append(addrs, r.Address)
			}
		}
		cs := make([]gjallarhorn.NSClass, 0, len(nsc))
		for _, c := range nsc {
			cs = append(cs, gjallarhorn.NSClass{Pattern: c.Pattern, Kind: c.Kind, Label: c.Label})
		}

		limits.update(enabled)
		classes.Store(&cs)
		tr.prune(watched)
		sched.Update(sd, addrs)
		log.Info("watchlist reloaded", "domains", len(sd), "resolvers", len(addrs), "ns_classes", len(cs))
		if len(addrs) == 0 {
			log.Warn("no enabled resolver: nothing will be measured")
		}
		return nil
	}
	if err := retry(ctx, log, "reload", reload); err != nil {
		return err
	}

	writer := chs.NewWriter(cfg.BatchSize, cfg.BatchFlush, log)
	writerDone := make(chan struct{})
	go func() {
		writer.Run(items)
		close(writerDone)
	}()

	go func() {
		t := time.NewTicker(cfg.ReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := reload(); err != nil {
					log.Error("reload failed", "err", err)
				}
			}
		}
	}()

	client := resolver.New(cfg.DNSTimeout)
	var wg sync.WaitGroup
	for range cfg.Workers {
		wg.Go(func() {
			for job := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if err := limits.wait(ctx, job.Resolver); err != nil {
					continue
				}
				obs := client.Resolve(context.WithoutCancel(ctx), job.Resolver, job.Domain, job.QType)
				changes, events := tr.observe(obs, job.Campaign, *classes.Load())
				items <- ch.Item{Obs: obs, Changes: changes, Events: events}
			}
		})
	}

	log.Info("collector started", "workers", cfg.Workers)
	sched.Run(ctx)
	close(jobs)
	wg.Wait()
	close(items)
	<-writerDone
	log.Info("stopped")
	return nil
}

func retry(ctx context.Context, log *slog.Logger, what string, fn func() error) error {
	delay := time.Second
	for {
		err := fn()
		if err == nil {
			return nil
		}
		log.Warn("retrying", "what", what, "err", err, "in", delay.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}

var errUnknownResolver = errors.New("resolver no longer enabled")

type limiters struct {
	mu sync.RWMutex
	m  map[string]*rate.Limiter
}

func (l *limiters) update(rs []pg.Resolver) {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := make(map[string]*rate.Limiter, len(rs))
	for _, r := range rs {
		qps := max(r.QPS, 1)
		if lim, ok := l.m[r.Address]; ok {
			lim.SetLimit(rate.Limit(qps))
			lim.SetBurst(qps)
			next[r.Address] = lim
			continue
		}
		next[r.Address] = rate.NewLimiter(rate.Limit(qps), qps)
	}
	l.m = next
}

func (l *limiters) wait(ctx context.Context, addr string) error {
	l.mu.RLock()
	lim := l.m[addr]
	l.mu.RUnlock()
	if lim == nil {
		return errUnknownResolver
	}
	return lim.Wait(ctx)
}
