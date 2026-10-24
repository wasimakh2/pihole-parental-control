package app

import (
	"sync"
	"time"
)

const (
	maxFailures  = 5
	lockDuration = time.Minute
	maxLock      = time.Hour
	// failWindow forgets old typos, so scattered mistakes over days never lock anyone out.
	failWindow = 15 * time.Minute
	// Escalation is remembered this long after a lockout ends.
	memory  = 24 * time.Hour
	pruneAt = 1000
)

// failLimiter locks out a host after maxFailures wrong passwords within failWindow.
// Each further lockout doubles, up to maxLock, so guessing stays slow over hours too.
type failLimiter struct {
	mu        sync.Mutex
	hosts     map[string]*failures
	now       func() time.Time
	lastPrune time.Time
}

type failures struct {
	count int
	first time.Time
	until time.Time
	locks int
}

func newFailLimiter() *failLimiter {
	return &failLimiter{hosts: map[string]*failures{}, now: time.Now}
}

func (l *failLimiter) blocked(host string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.hosts[host]
	return f != nil && l.now().Before(f.until)
}

func (l *failLimiter) fail(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	f := l.hosts[host]
	if f == nil {
		// Bounded memory: once full, new hosts are not tracked until old ones age out.
		if len(l.hosts) >= pruneAt && !l.prune(now) {
			return
		}
		f = &failures{}
		l.hosts[host] = f
	}
	if f.count == 0 || now.Sub(f.first) > failWindow {
		f.count, f.first = 0, now
	}
	f.count++
	if f.count >= maxFailures {
		f.count = 0
		f.locks++
		f.until = now.Add(lockFor(f.locks))
	}
}

// succeed clears a host's record once it logs in, unless it is still locked out.
func (l *failLimiter) succeed(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.hosts[host]; f != nil && !l.now().Before(f.until) {
		delete(l.hosts, host)
	}
}

// lockFor doubles lockDuration per lockout, capped at maxLock without overflowing.
func lockFor(locks int) time.Duration {
	d := lockDuration
	for i := 1; i < locks && d < maxLock; i++ {
		d *= 2
	}
	return min(d, maxLock)
}

// prune drops hosts idle for longer than memory, at most once a minute so a full
// map cannot turn every failure into a full scan. Caller holds l.mu.
func (l *failLimiter) prune(now time.Time) bool {
	if now.Sub(l.lastPrune) < time.Minute {
		return false
	}
	l.lastPrune = now
	for host, f := range l.hosts {
		if now.Sub(f.until) > memory && now.Sub(f.first) > failWindow {
			delete(l.hosts, host)
		}
	}
	return len(l.hosts) < pruneAt
}
