package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a keyed token bucket, used for login attempts per IP and per
// username.
type Limiter struct {
	every time.Duration
	burst int

	mu   sync.Mutex
	keys map[string]*limiterEntry
}

type limiterEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

func NewLimiter(every time.Duration, burst int) *Limiter {
	return &Limiter{every: every, burst: burst, keys: make(map[string]*limiterEntry)}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.keys[key]
	if !ok {
		e = &limiterEntry{lim: rate.NewLimiter(rate.Every(l.every), l.burst)}
		l.keys[key] = e
	}
	e.seen = time.Now()
	return e.lim.Allow()
}

// Sweep forgets keys idle long enough for their bucket to be full again.
func (l *Limiter) Sweep() {
	idle := l.every * time.Duration(l.burst)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.keys {
		if time.Since(e.seen) > idle {
			delete(l.keys, k)
		}
	}
}
