package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

const prefix = "HEIMDALL_"

type Config struct {
	PGDSN string

	CHAddr     string
	CHDatabase string
	CHUser     string
	CHPassword string

	ReloadInterval time.Duration
	Workers        int
	DNSTimeout     time.Duration
	BatchSize      int
	BatchFlush     time.Duration
	RemovalGrace   int
	StateSnapshot  time.Duration
	FirstRunSpread time.Duration

	Listen         string
	InsecureCookie bool
	SessionTTL     time.Duration
	Migrate        bool

	LogLevel slog.Level
}

func Load() (*Config, error) {
	var p parser
	c := &Config{
		PGDSN: p.str("PG_DSN", ""),

		CHAddr:     p.str("CH_ADDR", "localhost:9000"),
		CHDatabase: p.str("CH_DATABASE", "heimdall"),
		CHUser:     p.str("CH_USER", "default"),
		CHPassword: p.str("CH_PASSWORD", ""),

		ReloadInterval: p.duration("RELOAD_INTERVAL", 60*time.Second),
		Workers:        p.int("WORKERS", 32),
		DNSTimeout:     p.duration("DNS_TIMEOUT", 3*time.Second),
		BatchSize:      p.int("BATCH_SIZE", 5000),
		BatchFlush:     p.duration("BATCH_FLUSH", 5*time.Second),
		RemovalGrace:   p.int("REMOVAL_GRACE", 3),
		StateSnapshot:  p.duration("STATE_SNAPSHOT", time.Minute),
		FirstRunSpread: p.duration("FIRST_RUN_SPREAD", 5*time.Minute),

		Listen:         p.str("LISTEN", ":8080"),
		InsecureCookie: p.bool("INSECURE_COOKIE", false),
		SessionTTL:     p.duration("SESSION_TTL", 12*time.Hour),
		Migrate:        p.bool("MIGRATE", true),

		LogLevel: p.level("LOG_LEVEL", slog.LevelInfo),
	}
	if c.PGDSN == "" {
		p.fail("PG_DSN", errors.New("required"))
	}
	p.positive("WORKERS", c.Workers)
	p.positive("BATCH_SIZE", c.BatchSize)
	p.positive("REMOVAL_GRACE", c.RemovalGrace)
	p.positive("STATE_SNAPSHOT", int(c.StateSnapshot))
	p.positive("FIRST_RUN_SPREAD", int(c.FirstRunSpread))
	p.positive("RELOAD_INTERVAL", int(c.ReloadInterval))
	p.positive("DNS_TIMEOUT", int(c.DNSTimeout))
	p.positive("BATCH_FLUSH", int(c.BatchFlush))
	p.positive("SESSION_TTL", int(c.SessionTTL))
	if err := errors.Join(p.errs...); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Logger(component string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: c.LogLevel})
	return slog.New(h).With("component", component)
}

type parser struct{ errs []error }

func (p *parser) fail(key string, err error) {
	p.errs = append(p.errs, fmt.Errorf("%s%s: %w", prefix, key, err))
}

func (p *parser) lookup(key string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(prefix + key))
	return v, v != ""
}

func (p *parser) str(key, def string) string {
	if v, ok := p.lookup(key); ok {
		return v
	}
	return def
}

func (p *parser) int(key string, def int) int {
	v, ok := p.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		p.fail(key, err)
		return def
	}
	return n
}

func (p *parser) bool(key string, def bool) bool {
	v, ok := p.lookup(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.fail(key, err)
		return def
	}
	return b
}

func (p *parser) duration(key string, def time.Duration) time.Duration {
	v, ok := p.lookup(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		p.fail(key, err)
		return def
	}
	return d
}

func (p *parser) level(key string, def slog.Level) slog.Level {
	v, ok := p.lookup(key)
	if !ok {
		return def
	}
	var l slog.Level
	if err := l.UnmarshalText([]byte(v)); err != nil {
		p.fail(key, err)
		return def
	}
	return l
}

func (p *parser) positive(key string, n int) {
	if n <= 0 {
		p.fail(key, errors.New("must be positive"))
	}
}
