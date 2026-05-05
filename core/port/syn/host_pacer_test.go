package syn

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/XinRoom/go-portScan/core/port"
)

func TestHostPacerFastHostWaitsLessThanSlowHost(t *testing.T) {
	now := time.Unix(100, 0)
	p := port.NewHostPacerStore(100, time.Minute, func() time.Time { return now })
	p.Observe("fast", port.HostSample{RTT: 20 * time.Millisecond, HasRTT: true})
	p.Observe("slow", port.HostSample{RTT: 200 * time.Millisecond, HasRTT: true})

	fastDelay := p.DebugSnapshot("fast", now).NextDelay
	slowDelay := p.DebugSnapshot("slow", now).NextDelay
	if !(fastDelay < slowDelay) {
		t.Fatalf("expected fast host delay %s to be less than slow host delay %s", fastDelay, slowDelay)
	}
}

func TestHostPacerUsesConfigurableRTTFactor(t *testing.T) {
	now := time.Unix(100, 0)
	p := port.NewHostPacerStore(100, time.Minute, func() time.Time { return now })
	p.SetRTTFactor(1, 4)
	p.Observe("host", port.HostSample{RTT: 200 * time.Millisecond, HasRTT: true})

	snap := p.DebugSnapshot("host", now)
	delay := snap.NextDelay
	want := snap.BaseGap + 50*time.Millisecond
	if delay != want {
		t.Fatalf("expected delay %s with RTT factor 1/4, got %s", want, delay)
	}
}

func TestHostPacerCapsRTTExtraGap(t *testing.T) {
	now := time.Unix(100, 0)
	p := port.NewHostPacerStore(100, time.Minute, func() time.Time { return now })
	p.SetMaxRTTExtra(120 * time.Millisecond)
	p.Observe("host", port.HostSample{RTT: 800 * time.Millisecond, HasRTT: true})

	snap := p.DebugSnapshot("host", now)
	delay := snap.NextDelay
	want := snap.BaseGap + 120*time.Millisecond
	if delay != want {
		t.Fatalf("expected capped delay %s, got %s", want, delay)
	}
}

func TestHostPacerWaitHonorsContextCancellation(t *testing.T) {
	now := time.Unix(100, 0)
	p := port.NewHostPacerStore(100, time.Minute, func() time.Time { return now })
	p.Observe("host", port.HostSample{RTT: 200 * time.Millisecond, HasRTT: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Wait(ctx, "host"); err == nil {
		t.Fatal("expected canceled context to abort wait")
	}
}

func TestHostPacerObserveLogsSignificantDelayChanges(t *testing.T) {
	now := time.Unix(100, 0)
	var logs []string
	p := port.NewHostPacerStore(100, time.Minute, func() time.Time { return now })
	p.SetDebug(true, func(format string, args ...interface{}) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})

	p.Observe("127.0.0.1", port.HostSample{RTT: 200 * time.Millisecond, HasRTT: true})
	if len(logs) != 1 {
		t.Fatalf("expected one log after initial pacing change, got %v", logs)
	}
	if logs[0] == "" {
		t.Fatal("expected non-empty debug log")
	}
	if logs[0] != "[d] host pacing:127.0.0.1 base=10ms rtt_extra=100ms target_gap=110ms srtt=200ms reason=rtt\n" {
		t.Fatalf("unexpected debug log: %q", logs[0])
	}

	now = now.Add(10 * time.Millisecond)
	p.Observe("127.0.0.1", port.HostSample{RTT: 201 * time.Millisecond, HasRTT: true})
	if len(logs) != 1 {
		t.Fatalf("expected tiny pacing change not to log, got %v", logs)
	}

	now = now.Add(10 * time.Millisecond)
	p.Observe("127.0.0.1", port.HostSample{RTT: 0, HasRTT: true})
	if len(logs) != 2 {
		t.Fatalf("expected major pacing change to log again, got %v", logs)
	}
}
