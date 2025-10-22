package server

import (
	"sync"
	"time"
)

type attemptTracker struct {
	mu            sync.Mutex
	states        map[string]*attemptState
	maxAttempts   int
	lockout       time.Duration
	attemptWindow time.Duration
}

type attemptState struct {
	attempts    int
	windowStart time.Time
	lockedUntil time.Time
}

func newAttemptTracker(maxAttempts int, lockout, window time.Duration) *attemptTracker {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if lockout <= 0 {
		lockout = time.Minute
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &attemptTracker{
		states:        make(map[string]*attemptState),
		maxAttempts:   maxAttempts,
		lockout:       lockout,
		attemptWindow: window,
	}
}

func (t *attemptTracker) status(ip string) (locked bool, remaining time.Duration, attemptsLeft int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.getOrCreate(ip)
	now := time.Now()

	if now.After(st.lockedUntil) && !st.lockedUntil.IsZero() {
		st.lockedUntil = time.Time{}
	}

	if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
		return true, st.lockedUntil.Sub(now), 0
	}

	t.maybeResetWindow(st, now)
	left := t.maxAttempts - st.attempts
	if left < 0 {
		left = 0
	}
	return false, 0, left
}

func (t *attemptTracker) recordSuccess(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if st, ok := t.states[ip]; ok {
		st.attempts = 0
		st.windowStart = time.Time{}
		st.lockedUntil = time.Time{}
	}
}

func (t *attemptTracker) recordFailure(ip string) (attemptsLeft int, locked bool, lockout time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.getOrCreate(ip)
	now := time.Now()

	if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
		return 0, true, st.lockedUntil.Sub(now)
	}

	t.maybeResetWindow(st, now)

	st.attempts++
	if st.attempts >= t.maxAttempts {
		st.lockedUntil = now.Add(t.lockout)
		st.attempts = 0
		st.windowStart = time.Time{}
		return 0, true, t.lockout
	}

	st.lastAttempt(now)
	return t.maxAttempts - st.attempts, false, 0
}

func (t *attemptTracker) getOrCreate(ip string) *attemptState {
	st, ok := t.states[ip]
	if !ok {
		st = &attemptState{}
		t.states[ip] = st
	}
	return st
}

func (t *attemptTracker) maybeResetWindow(st *attemptState, now time.Time) {
	if st.windowStart.IsZero() {
		st.windowStart = now
		return
	}
	if now.Sub(st.windowStart) > t.attemptWindow {
		st.attempts = 0
		st.windowStart = now
	}
}

func (s *attemptState) lastAttempt(now time.Time) {
	if s.windowStart.IsZero() {
		s.windowStart = now
	}
}
