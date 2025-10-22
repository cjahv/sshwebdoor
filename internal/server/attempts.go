package server

import (
	"sync"
	"time"
)

type attemptTracker struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	lockouts map[string]time.Time

	maxAttempts   int
	lockout       time.Duration
	attemptWindow time.Duration
}

func newAttemptTracker(maxAttempts int, lockoutSeconds, windowSeconds int) *attemptTracker {
	return &attemptTracker{
		attempts:      make(map[string][]time.Time),
		lockouts:      make(map[string]time.Time),
		maxAttempts:   maxAttempts,
		lockout:       time.Duration(lockoutSeconds) * time.Second,
		attemptWindow: time.Duration(windowSeconds) * time.Second,
	}
}

func (a *attemptTracker) remaining(host string, now time.Time) (remaining int, locked bool, unlockIn time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if deadline, ok := a.lockouts[host]; ok {
		if now.Before(deadline) {
			return 0, true, deadline.Sub(now)
		}
		delete(a.lockouts, host)
	}

	a.trimLocked(host, now)
	attempts := a.attempts[host]
	if len(attempts) >= a.maxAttempts {
		return 0, false, 0
	}
	return a.maxAttempts - len(attempts), false, 0
}

func (a *attemptTracker) recordFailure(host string, now time.Time) (remaining int, locked bool, unlockIn time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if deadline, ok := a.lockouts[host]; ok {
		if now.Before(deadline) {
			return 0, true, deadline.Sub(now)
		}
		delete(a.lockouts, host)
	}
	a.trimLocked(host, now)
	attempts := append(a.attempts[host], now)
	a.attempts[host] = attempts
	if len(attempts) >= a.maxAttempts {
		deadline := now.Add(a.lockout)
		a.lockouts[host] = deadline
		return 0, true, a.lockout
	}
	return a.maxAttempts - len(attempts), false, 0
}

func (a *attemptTracker) clear(host string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.attempts, host)
	delete(a.lockouts, host)
}

func (a *attemptTracker) trimLocked(host string, now time.Time) {
	if a.attemptWindow <= 0 {
		return
	}
	attempts := a.attempts[host]
	if len(attempts) == 0 {
		return
	}
	cutoff := now.Add(-a.attemptWindow)
	idx := 0
	for idx < len(attempts) && attempts[idx].Before(cutoff) {
		idx++
	}
	if idx > 0 {
		attempts = attempts[idx:]
		if len(attempts) == 0 {
			delete(a.attempts, host)
		} else {
			a.attempts[host] = attempts
		}
	}
}
