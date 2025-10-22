package daemon

import (
	"sync"
	"time"

	"sshwebdoor/internal/config"
)

type attemptState struct {
	count     int
	first     time.Time
	lockUntil time.Time
}

type attemptManager struct {
	cfg *config.Config
	mu  sync.Mutex
	m   map[string]*attemptState
}

func newAttemptManager(cfg *config.Config) *attemptManager {
	return &attemptManager{
		cfg: cfg,
		m:   make(map[string]*attemptState),
	}
}

func (am *attemptManager) status(remote string) (locked bool, remaining int, unlock time.Time) {
	am.mu.Lock()
	defer am.mu.Unlock()

	st, ok := am.m[remote]
	if !ok {
		return false, am.cfg.MaxAttempts, time.Time{}
	}
	now := time.Now()
	if st.lockUntil.After(now) {
		return true, 0, st.lockUntil
	}
	if !st.lockUntil.IsZero() {
		st.lockUntil = time.Time{}
	}
	if st.first.IsZero() || now.Sub(st.first) > time.Duration(am.cfg.AttemptWindowSeconds)*time.Second {
		st.count = 0
		st.first = time.Time{}
	}
	remaining = am.cfg.MaxAttempts - st.count
	if remaining < 0 {
		remaining = 0
	}
	return false, remaining, time.Time{}
}

func (am *attemptManager) recordFailure(remote string) (remaining int, lockUntil time.Time) {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	st, ok := am.m[remote]
	if !ok {
		st = &attemptState{}
		am.m[remote] = st
	}
	if st.lockUntil.After(now) {
		return 0, st.lockUntil
	}
	if st.first.IsZero() || now.Sub(st.first) > time.Duration(am.cfg.AttemptWindowSeconds)*time.Second {
		st.first = now
		st.count = 0
	}
	st.count++
	if st.count >= am.cfg.MaxAttempts {
		st.lockUntil = now.Add(time.Duration(am.cfg.LockoutSeconds) * time.Second)
		st.count = 0
		st.first = time.Time{}
		return 0, st.lockUntil
	}
	remaining = am.cfg.MaxAttempts - st.count
	return remaining, time.Time{}
}

func (am *attemptManager) recordSuccess(remote string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	delete(am.m, remote)
}
