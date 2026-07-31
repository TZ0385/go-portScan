package port

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestHostLimiterStoreDisabledReturnsImmediately(t *testing.T) {
	store := newHostLimiterStore(0, time.Minute, time.Now)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if err := store.wait(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("expected disabled store to return immediately, got %v", err)
	}

	option := ScannerOption{RatePreHost: 3}
	if option.RatePreHost != 3 {
		t.Fatalf("expected RatePreHost to be stored on ScannerOption, got %d", option.RatePreHost)
	}
}

func TestHostLimiterStoreThrottlesPerHost(t *testing.T) {
	store := newHostLimiterStore(1, time.Minute, time.Now)

	if err := store.wait(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("expected first request for host to pass, got %v", err)
	}

	blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := store.wait(blockedCtx, "127.0.0.1"); err == nil {
		t.Fatal("expected second request for same host to be throttled")
	}

	if err := store.wait(context.Background(), "127.0.0.2"); err != nil {
		t.Fatalf("expected different host not to be blocked, got %v", err)
	}
}

func TestHostLimiterStoreSweepsExpiredEntries(t *testing.T) {
	now := time.Unix(100, 0)
	store := newHostLimiterStore(1, time.Minute, func() time.Time {
		return now
	})

	if err := store.wait(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("expected first host to be created, got %v", err)
	}
	now = now.Add(2 * time.Minute)

	if err := store.wait(context.Background(), "127.0.0.2"); err != nil {
		t.Fatalf("expected second host to be created, got %v", err)
	}

	if count := countHostLimiterEntries(&store.entries); count != 1 {
		t.Fatalf("expected expired entries to be swept, got %d entries", count)
	}
	if _, ok := store.entries.Load("127.0.0.1"); ok {
		t.Fatal("expected expired host entry to be removed")
	}
}

func TestHostLimiterStoreDefersFullSweepUntilInterval(t *testing.T) {
	now := time.Unix(100, 0)
	store := newHostLimiterStore(1, time.Minute, func() time.Time { return now })

	stale := &hostLimiterEntry{
		limiter:  rate.NewLimiter(1, 1),
		lastSeen: now.Add(-2 * time.Minute),
	}
	store.entries.Store("stale-host", stale)

	// 清理周期未到时，新 host 不应触发全表扫描。
	if err := store.wait(context.Background(), "new-host"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.entries.Load("stale-host"); !ok {
		t.Fatal("expected full sweep to be deferred until its interval")
	}

	now = now.Add(time.Minute)
	if err := store.wait(context.Background(), "next-host"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.entries.Load("stale-host"); ok {
		t.Fatal("expected stale entry to be removed when sweep interval elapsed")
	}
}

func TestHostLimiterStoreReplacesExpiredEntryForSameHost(t *testing.T) {
	now := time.Unix(100, 0)
	store := newHostLimiterStore(1, time.Minute, func() time.Time {
		return now
	})

	first := store.acquireOrCreate("127.0.0.1", now)
	first.release(now)
	now = now.Add(2 * time.Minute)
	second := store.acquireOrCreate("127.0.0.1", now)
	second.release(now)

	if first == second {
		t.Fatal("expected expired host entry to be replaced for same host")
	}

	current, ok := store.entries.Load("127.0.0.1")
	if !ok {
		t.Fatal("expected host entry to remain in store")
	}
	if current.(*hostLimiterEntry) != second {
		t.Fatal("expected store to keep the new host entry")
	}
}

func TestHostLimiterStoreDoesNotReplaceExpiredLookingEntryWithActiveWaiters(t *testing.T) {
	now := time.Unix(100, 0)
	store := newHostLimiterStore(1, time.Minute, func() time.Time {
		return now
	})
	host := "127.0.0.1"

	originalEntry := store.acquireOrCreate(host, now)
	defer originalEntry.release(now)

	queuedEntry := store.acquireOrCreate(host, now)
	if queuedEntry != originalEntry {
		t.Fatal("expected queued waiter to reuse the same host entry")
	}
	defer queuedEntry.release(now)

	now = now.Add(2 * time.Minute)
	store.sweepExpired(now)

	current, ok := store.entries.Load(host)
	if !ok {
		t.Fatal("expected active host entry not to be swept")
	}
	if current.(*hostLimiterEntry) != originalEntry {
		t.Fatal("expected sweep to keep original host entry while waiters are active")
	}

	reused := store.acquireOrCreate(host, now)
	if reused != originalEntry {
		t.Fatal("expected active host entry not to be replaced while waiters are queued")
	}
	reused.release(now)
}

func countHostLimiterEntries(entries *sync.Map) int {
	count := 0
	entries.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
