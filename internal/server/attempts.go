package server

import (
	"sync"
	"time"
)

type attemptInfo struct {
	Attempts     int
	LastAttempt  time.Time
	LockoutUntil time.Time
}

// AttemptTracker tracks login attempts per remote address.
type AttemptTracker struct {
	mu      sync.Mutex
	entries map[string]*attemptInfo
	max     int
	window  time.Duration
	lockout time.Duration
}

// NewAttemptTracker constructs a tracker with the configured thresholds.
func NewAttemptTracker(maxAttempts int, window, lockout time.Duration) *AttemptTracker {
	return &AttemptTracker{
		entries: make(map[string]*attemptInfo),
		max:     maxAttempts,
		window:  window,
		lockout: lockout,
	}
}

// RegisterFailure updates the tracker with a failed attempt and returns the remaining attempts and optional lockout duration.
func (t *AttemptTracker) RegisterFailure(addr string) (remaining int, lockedUntil time.Time) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.getOrCreate(addr)
	if entry.LockoutUntil.After(now) {
		return 0, entry.LockoutUntil
	}
	if entry.LastAttempt.IsZero() || now.Sub(entry.LastAttempt) > t.window {
		entry.Attempts = 0
	}
	entry.Attempts++
	entry.LastAttempt = now
	if entry.Attempts >= t.max {
		entry.LockoutUntil = now.Add(t.lockout)
		entry.Attempts = 0
		return 0, entry.LockoutUntil
	}
	entry.LockoutUntil = time.Time{}
	return t.max - entry.Attempts, time.Time{}
}

// RegisterSuccess resets counters for the provided address.
func (t *AttemptTracker) RegisterSuccess(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, addr)
}

// AttemptsRemaining returns the remaining attempts and lockout expiry, if any, for an address.
func (t *AttemptTracker) AttemptsRemaining(addr string) (int, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[addr]
	if entry == nil {
		return t.max, time.Time{}
	}
	now := time.Now()
	if entry.LockoutUntil.After(now) {
		return 0, entry.LockoutUntil
	}
	if entry.LastAttempt.IsZero() || now.Sub(entry.LastAttempt) > t.window {
		entry.Attempts = 0
		entry.LastAttempt = time.Time{}
	}
	remaining := t.max - entry.Attempts
	if remaining < 0 {
		remaining = 0
	}
	return remaining, time.Time{}
}

func (t *AttemptTracker) getOrCreate(addr string) *attemptInfo {
	entry := t.entries[addr]
	if entry == nil {
		entry = &attemptInfo{}
		t.entries[addr] = entry
	}
	return entry
}

// RemainingLockout returns the lockout expiry when the address is currently blocked.
func (t *AttemptTracker) RemainingLockout(addr string) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.entries[addr]; ok {
		return entry.LockoutUntil
	}
	return time.Time{}
}
