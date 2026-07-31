//go:build !nosyn

package syn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinRoom/go-portScan/core/port"
	"github.com/google/gopacket/pcap"
	limiter "golang.org/x/time/rate"
)

func TestSynAdaptiveLimiterDisabledWithoutValidMiniRate(t *testing.T) {
	now := time.Unix(100, 0)
	for _, minRate := range []int{0, -1, 600, 700} {
		controller := newSynAdaptiveLimiter(600, minRate, now)
		if controller.enabled {
			t.Fatalf("miniRate=%d should keep fixed-rate mode", minRate)
		}
		if controller.shouldSampleProbe() {
			t.Fatalf("miniRate=%d should not enable timeout retry", minRate)
		}
	}
}

func TestSynAdaptiveLimiterDropsOnLocalCongestion(t *testing.T) {
	now := time.Unix(100, 0)
	controller := newSynAdaptiveLimiter(600, 300, now)
	rate, reason, changed := evaluateAdaptiveForTest(t, controller, now.Add(2*time.Second), 100, 10000, &pcap.Stats{PacketsDropped: 1})
	if !changed || rate != 420 || reason != "local_congestion" {
		t.Fatalf("unexpected adjustment rate=%d reason=%q changed=%t", rate, reason, changed)
	}

	controller.recordWriteError()
	rate, _, _ = evaluateAdaptiveForTest(t, controller, now.Add(4*time.Second), 100, 10000, &pcap.Stats{PacketsDropped: 1})
	if rate != 300 {
		t.Fatalf("second congestion window should clamp to miniRate, got %d", rate)
	}
}

func TestSynAdaptiveLimiterDropsWhenPendingIsHigh(t *testing.T) {
	now := time.Unix(100, 0)
	controller := newSynAdaptiveLimiter(600, 300, now)
	rate, reason, changed := evaluateAdaptiveForTest(t, controller, now.Add(2*time.Second), 7000, 10000, nil)
	if !changed || rate != 420 || reason != "local_congestion" {
		t.Fatalf("unexpected pending adjustment rate=%d reason=%q changed=%t", rate, reason, changed)
	}
}

func TestSynAdaptiveLimiterUsesRetryRecoveryAndRecoversSlowly(t *testing.T) {
	now := time.Unix(100, 0)
	controller := newSynAdaptiveLimiter(600, 300, now)
	for i := 0; i < 5; i++ {
		controller.recordRetry(i < 2)
	}
	rate, reason, changed := evaluateAdaptiveForTest(t, controller, now.Add(2*time.Second), 0, 10000, nil)
	if !changed || rate != 480 || reason != "retry_recovered" {
		t.Fatalf("unexpected retry adjustment rate=%d reason=%q changed=%t", rate, reason, changed)
	}

	for window := 2; window <= 4; window++ {
		rate, reason, changed = evaluateAdaptiveForTest(t, controller, now.Add(time.Duration(window)*2*time.Second), 0, 10000, nil)
	}
	if !changed || rate != 510 || reason != "healthy_recovery" {
		t.Fatalf("expected one slow recovery step, rate=%d reason=%q changed=%t", rate, reason, changed)
	}
}

func evaluateAdaptiveForTest(t *testing.T, controller *synAdaptiveLimiter, now time.Time, pending, capacity int, stats *pcap.Stats) (int, string, bool) {
	t.Helper()
	if !controller.beginEvaluation(now) {
		t.Fatal("expected adaptive evaluation window to be due")
	}
	return controller.evaluateClaimed(pending, capacity, stats)
}

func TestSynAdaptiveLimiterSamplesExactlyOnePercent(t *testing.T) {
	controller := newSynAdaptiveLimiter(600, 300, time.Now())
	for i := 1; i < 100; i++ {
		if controller.shouldSampleProbe() {
			t.Fatalf("probe %d should not be sampled", i)
		}
	}
	if !controller.shouldSampleProbe() {
		t.Fatal("probe 100 should be sampled")
	}
}

func TestApplyAdaptiveRateUpdatesRateAndBurst(t *testing.T) {
	l := limiter.NewLimiter(600, 6)
	applyAdaptiveRate(l, time.Now(), 300)
	if l.Limit() != 300 || l.Burst() != 3 {
		t.Fatalf("unexpected limiter state rate=%v burst=%d", l.Limit(), l.Burst())
	}
}

func TestSynScannerReadsPcapStatsOncePerEvaluationWindow(t *testing.T) {
	now := time.Unix(100, 0)
	var calls atomic.Int32
	ss := &SynScanner{
		option:   port.ScannerOption{Rate: 600, MiniRate: 300},
		limiter:  limiter.NewLimiter(600, 6),
		adaptive: newSynAdaptiveLimiter(600, 300, now),
		pcapStats: func() (*pcap.Stats, error) {
			calls.Add(1)
			return &pcap.Stats{}, nil
		},
	}
	for i := 0; i < 100; i++ {
		ss.evaluateAdaptiveRate(now.Add(2 * time.Second))
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one pcap stats read per window, got %d", calls.Load())
	}
}

func TestSynScannerAdaptiveWaitCoversRetryWindow(t *testing.T) {
	ss := &SynScanner{
		option:   port.ScannerOption{Rate: 600, MiniRate: 300, Timeout: 1200},
		adaptive: newSynAdaptiveLimiter(600, 300, time.Now()),
	}
	want := 2*1200*time.Millisecond + 2*watchIpStatusSweepInterval + 100*time.Millisecond
	if got := ss.pendingProbeWaitDuration(); got != want {
		t.Fatalf("adaptive pending wait=%s, want %s", got, want)
	}
}

func TestSynSampledRetryEmitsOnlyOneTerminalEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	table := newWatchIpStatusTable(20 * time.Millisecond)
	defer table.Close()

	controller := newSynAdaptiveLimiter(600, 300, time.Now())
	ss := &SynScanner{
		ctx:            ctx,
		cancel:         cancel,
		option:         port.ScannerOption{Rate: 600, MiniRate: 300},
		limiter:        limiter.NewLimiter(600, 6),
		adaptive:       controller,
		retryChan:      make(chan pendingProbe, 64),
		watchIpStatusT: table,
	}
	table.onProbeTimeout = ss.handleProbeTimeout
	ss.retryWg.Add(1)
	go func() {
		defer ss.retryWg.Done()
		ss.retryLoop()
	}()
	defer func() {
		cancel()
		ss.retryWg.Wait()
	}()

	events := make(chan port.ProbeEvent, 2)
	key, _, ok := table.ReserveProbeContext(ctx, nil, "192.0.2.10", 443, time.Now(), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})
	if !ok {
		t.Fatal("failed to reserve probe")
	}
	var sends atomic.Int32
	if !table.SetRetry(key, func() error {
		sends.Add(1)
		return nil
	}) {
		t.Fatal("failed to attach retry")
	}

	select {
	case event := <-events:
		if event.Outcome != port.ProbeNoResponse {
			t.Fatalf("unexpected terminal event: %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sampled retry terminal event")
	}
	if sends.Load() != 1 {
		t.Fatalf("expected exactly one retry send, got %d", sends.Load())
	}
	select {
	case event := <-events:
		t.Fatalf("expected one terminal event, got extra %#v", event)
	default:
	}
}

func TestSynSampledRetryQueueFullFallsBackToNormalTimeout(t *testing.T) {
	controller := newSynAdaptiveLimiter(600, 300, time.Now())
	table := newWatchIpStatusTable(time.Minute)
	defer table.Close()
	ss := &SynScanner{
		adaptive:       controller,
		retryChan:      make(chan pendingProbe),
		watchIpStatusT: table,
	}
	probe := pendingProbe{
		key:    probeKey{ip: "192.0.2.10", srcPort: 49152, dstPort: 443},
		ctx:    context.Background(),
		retry:  func() error { return nil },
		sentAt: time.Now(),
		option: port.IpOption{},
	}
	if ss.handleProbeTimeout(probe) {
		t.Fatal("full retry queue must fall back to the normal timeout path")
	}
	if !table.IsEmpty() {
		t.Fatal("queue-full fallback must remove the temporary retry reservation")
	}
}

func TestSynSampledRetrySendFailureEmitsOneProbeError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	table := newWatchIpStatusTable(20 * time.Millisecond)
	controller := newSynAdaptiveLimiter(600, 300, time.Now())
	ss := &SynScanner{
		ctx:            ctx,
		cancel:         cancel,
		option:         port.ScannerOption{Rate: 600, MiniRate: 300},
		limiter:        limiter.NewLimiter(600, 6),
		adaptive:       controller,
		retryChan:      make(chan pendingProbe, 64),
		watchIpStatusT: table,
	}
	table.onProbeTimeout = ss.handleProbeTimeout
	ss.retryWg.Add(1)
	go func() {
		defer ss.retryWg.Done()
		ss.retryLoop()
	}()
	defer func() {
		cancel()
		ss.retryWg.Wait()
		table.Close()
	}()

	events := make(chan port.ProbeEvent, 2)
	key, _, ok := table.ReserveProbeContext(ctx, nil, "192.0.2.10", 443, time.Now(), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})
	if !ok {
		t.Fatal("failed to reserve probe")
	}
	if !table.SetRetry(key, func() error { return errors.New("retry send failed") }) {
		t.Fatal("failed to attach retry")
	}

	select {
	case event := <-events:
		if event.Outcome != port.ProbeError || event.Err == nil {
			t.Fatalf("expected retry ProbeError, got %#v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for retry send failure")
	}
	if !table.IsEmpty() {
		t.Fatal("retry send failure must remove pending probe")
	}
	select {
	case event := <-events:
		t.Fatalf("expected one terminal event, got extra %#v", event)
	default:
	}
}

func TestSynRetryCancellationEmitsAborted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	table := newWatchIpStatusTable(time.Minute)
	defer table.Close()
	events := make(chan port.ProbeEvent, 1)
	key, _, ok := table.ReserveProbeContext(ctx, nil, "192.0.2.10", 443, time.Now(), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})
	if !ok {
		t.Fatal("failed to reserve probe")
	}
	cancel()
	ss := &SynScanner{watchIpStatusT: table}
	ss.finishRetryError(pendingProbe{key: key}, context.Canceled)

	select {
	case event := <-events:
		if event.Outcome != port.ProbeAborted {
			t.Fatalf("expected canceled retry to abort, got %#v", event)
		}
	default:
		t.Fatal("expected canceled retry terminal event")
	}
	if !table.IsEmpty() {
		t.Fatal("canceled retry must remove pending probe")
	}
}
