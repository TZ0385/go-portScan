package port

import (
	"context"
	"sync"
	"time"

	limiter "golang.org/x/time/rate"
)

type hostLimiterEntry struct {
	limiter  *limiter.Limiter
	lastSeen time.Time
	active   int
	mu       sync.Mutex
}

func (e *hostLimiterEntry) acquire(now time.Time) {
	e.mu.Lock()
	e.lastSeen = now
	e.active++
	e.mu.Unlock()
}


func (e *hostLimiterEntry) release(now time.Time) {
	e.mu.Lock()
	if e.active > 0 {
		e.active--
	}
	e.lastSeen = now
	e.mu.Unlock()
}

func (e *hostLimiterEntry) state() (time.Time, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastSeen, e.active
}

type HostLimiterStore struct {
	rate    int
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries sync.Map
}

func NewHostLimiterStore(ratePerHost int) *HostLimiterStore {
	if ratePerHost <= 0 {
		return nil
	}
	return newHostLimiterStore(ratePerHost, time.Minute, time.Now)
}

func newHostLimiterStore(ratePerHost int, ttl time.Duration, now func() time.Time) *HostLimiterStore {
	if now == nil {
		now = time.Now
	}
	return &HostLimiterStore{
		rate: ratePerHost,
		ttl:  ttl,
		now:  now,
	}
}

func (s *HostLimiterStore) Wait(ctx context.Context, host string) error {
	if s == nil || s.rate <= 0 {
		return nil
	}

	now := s.now()
	entry := s.acquireOrCreate(host, now)
	defer entry.release(s.now())
	return entry.limiter.Wait(ctx)
}

func (s *HostLimiterStore) wait(ctx context.Context, host string) error {
	return s.Wait(ctx, host)
}

func (s *HostLimiterStore) acquireOrCreate(host string, now time.Time) *hostLimiterEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.loadFresh(host, now); ok {
		entry.acquire(now)
		return entry
	}
	if entry, ok := s.entries.Load(host); ok && s.isExpired(entry.(*hostLimiterEntry), now) {
		s.entries.Delete(host)
	}

	// 仅在新增 host 时清理过期项，避免每次等待都全表扫描。
	s.sweepExpired(now)
	entry := &hostLimiterEntry{
		limiter:  limiter.NewLimiter(limiter.Limit(s.rate), 1),
		lastSeen: now,
	}
	entry.acquire(now)
	actual, _ := s.entries.LoadOrStore(host, entry)
	if actualEntry := actual.(*hostLimiterEntry); actualEntry != entry {
		actualEntry.acquire(now)
		return actualEntry
	}
	return entry
}

func (s *HostLimiterStore) loadOrCreate(host string, now time.Time) *hostLimiterEntry {
	if entry, ok := s.loadFresh(host, now); ok {
		return entry
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.loadFresh(host, now); ok {
		return entry
	}
	if entry, ok := s.entries.Load(host); ok && s.isExpired(entry.(*hostLimiterEntry), now) {
		s.entries.Delete(host)
	}

	// 仅在新增 host 时清理过期项，避免每次等待都全表扫描。
	s.sweepExpired(now)
	entry := &hostLimiterEntry{
		limiter:  limiter.NewLimiter(limiter.Limit(s.rate), 1),
		lastSeen: now,
	}
	actual, _ := s.entries.LoadOrStore(host, entry)
	return actual.(*hostLimiterEntry)
}

func (s *HostLimiterStore) loadFresh(host string, now time.Time) (*hostLimiterEntry, bool) {
	entry, ok := s.entries.Load(host)
	if !ok {
		return nil, false
	}
	hostEntry := entry.(*hostLimiterEntry)
	if s.isExpired(hostEntry, now) {
		return nil, false
	}
	return hostEntry, true
}

func (s *HostLimiterStore) isExpired(entry *hostLimiterEntry, now time.Time) bool {
	if s.ttl <= 0 {
		return false
	}
	lastSeen, active := entry.state()
	// 仍有进行中或排队中的 waiter 时，禁止回收该 host，避免创建新 limiter 绕过同 host 串行限制。
	if active > 0 {
		return false
	}
	return now.Sub(lastSeen) > s.ttl
}

func (s *HostLimiterStore) sweepExpired(now time.Time) {
	if s.ttl <= 0 {
		return
	}

	s.entries.Range(func(key, value any) bool {
		entry := value.(*hostLimiterEntry)
		if s.isExpired(entry, now) {
			s.entries.Delete(key)
		}
		return true
	})
}
