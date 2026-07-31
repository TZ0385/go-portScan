package port

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type HostSample struct {
	RTT    time.Duration
	HasRTT bool
}

type hostPacerEntry struct {
	mu              sync.Mutex
	srtt            time.Duration
	nextSendAt      time.Time
	lastLoggedDelay time.Duration
	lastSeen        time.Time
	baseGap         time.Duration
	maxExtraGap     time.Duration
}

func (e *hostPacerEntry) observe(now time.Time, sample HostSample, factorNum, factorDen int, maxRTTExtra time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastSeen = now
	if !sample.HasRTT {
		return
	}
	if e.srtt == 0 {
		e.srtt = sample.RTT
	} else {
		e.srtt = (e.srtt*7 + sample.RTT) / 8
	}
	delay := e.baseGap + e.extraGapLocked(factorNum, factorDen, maxRTTExtra)
	if delay < e.baseGap {
		delay = e.baseGap
	}
	e.nextSendAt = now.Add(delay)
}

func (e *hostPacerEntry) extraGapLocked(factorNum, factorDen int, maxRTTExtra time.Duration) time.Duration {
	if factorDen <= 0 || e.srtt <= 0 {
		return 0
	}
	extra := time.Duration(int64(e.srtt) * int64(factorNum) / int64(factorDen))
	if maxRTTExtra > 0 && extra > maxRTTExtra {
		extra = maxRTTExtra
	}
	if extra > e.maxExtraGap {
		return e.maxExtraGap
	}
	return extra
}

func (e *hostPacerEntry) nextDelay(now time.Time) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nextSendAt.IsZero() || !e.nextSendAt.After(now) {
		return 0
	}
	return e.nextSendAt.Sub(now)
}

type HostPacerSnapshot struct {
	Srtt      time.Duration
	BaseGap   time.Duration
	NextDelay time.Duration
}

type HostPacerStore struct {
	rate         int
	ttl          time.Duration
	now          func() time.Time
	mu           sync.Mutex
	store        map[string]*hostPacerEntry
	debug        bool
	debugf       func(string, ...interface{})
	rttFactorNum int
	rttFactorDen int
	maxRTTExtra  time.Duration
}

func NewHostPacerStore(ratePerHost int, ttl time.Duration, now func() time.Time) *HostPacerStore {
	if ratePerHost <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &HostPacerStore{
		rate:         ratePerHost,
		ttl:          ttl,
		now:          now,
		store:        make(map[string]*hostPacerEntry),
		rttFactorNum: 1,
		rttFactorDen: 2,
		maxRTTExtra:  250 * time.Millisecond,
		debugf: func(format string, args ...interface{}) {
			fmt.Printf(format, args...)
		},
	}
}

func (p *HostPacerStore) SetDebug(debug bool, debugf func(string, ...interface{})) {
	if p == nil {
		return
	}
	p.debug = debug
	if debugf != nil {
		p.debugf = debugf
	}
}

func (p *HostPacerStore) SetRTTFactor(num, den int) {
	if p == nil || den <= 0 {
		return
	}
	p.rttFactorNum = num
	p.rttFactorDen = den
}

func (p *HostPacerStore) SetMaxRTTExtra(max time.Duration) {
	if p == nil {
		return
	}
	p.maxRTTExtra = max
}

func (p *HostPacerStore) loadOrCreate(host string) *hostPacerEntry {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.store {
		v.mu.Lock()
		lastSeen := v.lastSeen
		v.mu.Unlock()
		if p.ttl > 0 && now.Sub(lastSeen) > p.ttl {
			delete(p.store, k)
		}
	}
	if entry, ok := p.store[host]; ok {
		entry.mu.Lock()
		entry.lastSeen = now
		entry.mu.Unlock()
		return entry
	}
	entry := &hostPacerEntry{lastSeen: now, baseGap: time.Second / time.Duration(p.rate), maxExtraGap: 2 * time.Second}
	p.store[host] = entry
	return entry
}

func (p *HostPacerStore) Observe(host string, sample HostSample) {
	if p == nil || host == "" {
		return
	}
	now := p.now()
	entry := p.loadOrCreate(host)
	entry.observe(now, sample, p.rttFactorNum, p.rttFactorDen, p.maxRTTExtra)
	p.logDelayChange(host, sample, entry, now)
}

func (p *HostPacerStore) DebugSnapshot(host string, now time.Time) HostPacerSnapshot {
	if p == nil || host == "" {
		return HostPacerSnapshot{}
	}
	entry := p.loadOrCreate(host)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	snap := HostPacerSnapshot{Srtt: entry.srtt, BaseGap: entry.baseGap}
	if !entry.nextSendAt.IsZero() && entry.nextSendAt.After(now) {
		snap.NextDelay = entry.nextSendAt.Sub(now)
	}
	return snap
}

func (p *HostPacerStore) rttExtra(entry *hostPacerEntry) time.Duration {
	entry.mu.Lock()
	srtt := entry.srtt
	entry.mu.Unlock()
	if srtt <= 0 || p.rttFactorDen <= 0 {
		return 0
	}
	extra := time.Duration(int64(srtt) * int64(p.rttFactorNum) / int64(p.rttFactorDen))
	if p.maxRTTExtra > 0 && extra > p.maxRTTExtra {
		return p.maxRTTExtra
	}
	return extra
}

func (p *HostPacerStore) logDelayChange(host string, sample HostSample, entry *hostPacerEntry, now time.Time) {
	if p == nil || !p.debug || p.debugf == nil {
		return
	}
	delay := entry.nextDelay(now)
	entry.mu.Lock()
	lastLoggedDelay := entry.lastLoggedDelay
	if lastLoggedDelay != 0 {
		diff := delay - lastLoggedDelay
		if diff < 0 {
			diff = -diff
		}
		if diff < 10*time.Millisecond {
			entry.mu.Unlock()
			return
		}
	}
	entry.lastLoggedDelay = delay
	srtt := entry.srtt
	baseGap := entry.baseGap
	entry.mu.Unlock()
	rttExtra := p.rttExtra(entry)
	targetGap := baseGap + rttExtra
	p.debugf("[d] host pacing:%s base=%s rtt_extra=%s target_gap=%s srtt=%s reason=rtt\n", host, baseGap, rttExtra, targetGap, srtt)
}

func (p *HostPacerStore) Wait(ctx context.Context, host string) error {
	if p == nil || host == "" {
		return nil
	}
	delay := p.loadOrCreate(host).nextDelay(p.now())
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
