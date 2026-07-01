package port

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNormalizeMiniRate(t *testing.T) {
	if got := NormalizeMiniRate(600, 300); got != 300 {
		t.Fatalf("expected mini rate 300, got %d", got)
	}
	if got := NormalizeMiniRate(100, 300); got != 100 {
		t.Fatalf("expected mini rate clamped to rate, got %d", got)
	}
	if got := NormalizeMiniRate(100, 0); got != 0 {
		t.Fatalf("expected zero mini rate unchanged, got %d", got)
	}
}

func TestFingerTimeout(t *testing.T) {
	if got := FingerTimeout(800, 0); got != 2000 {
		t.Fatalf("expected default finger timeout 2000ms, got %d", got)
	}
	if got := FingerTimeout(2800, 0); got != 2800 {
		t.Fatalf("expected scanner timeout to be reused when large enough, got %d", got)
	}
	if got := FingerTimeout(800, 3000); got != 3000 {
		t.Fatalf("expected explicit finger timeout, got %d", got)
	}
}

func TestIpOptionEmitProbeDoneFillsDefaults(t *testing.T) {
	done := make(chan ProbeEvent, 1)
	opt := IpOption{
		Ext: "marker",
		OnProbeDone: func(event ProbeEvent) {
			done <- event
		},
	}

	started := time.Now().Add(-time.Second)
	opt.EmitProbeDone(ProbeEvent{
		IP:        net.ParseIP("127.0.0.1"),
		Port:      443,
		Open:      true,
		Outcome:   ProbeOpen,
		StartedAt: started,
	})

	select {
	case event := <-done:
		if event.Port != 443 || !event.Open || event.Outcome != ProbeOpen {
			t.Fatalf("unexpected event: %#v", event)
		}
		if event.Ext != "marker" {
			t.Fatalf("expected Ext to be copied from option, got %#v", event.Ext)
		}
		if event.StartedAt != started {
			t.Fatalf("expected StartedAt to be preserved")
		}
		if event.FinishedAt.IsZero() {
			t.Fatal("expected FinishedAt to be populated")
		}
	default:
		t.Fatal("expected event callback")
	}
}

func TestIpOptionEmitProbeDoneNilCallbackIsNoop(t *testing.T) {
	IpOption{}.EmitProbeDone(ProbeEvent{
		IP:      net.ParseIP("127.0.0.1"),
		Port:    80,
		Outcome: ProbeClosed,
	})
}

func TestEmitOpenProbeResultQueuesResultBeforeEvent(t *testing.T) {
	ctx := context.Background()
	ret := make(chan OpenIpPort, 1)
	events := make(chan ProbeEvent, 1)
	started := time.Now().Add(-time.Second)
	result := OpenIpPort{
		Ip:   net.ParseIP("127.0.0.1"),
		Port: 8080,
		IpOption: IpOption{
			Ext: "marker",
			OnProbeDone: func(event ProbeEvent) {
				events <- event
			},
		},
	}

	if !EmitOpenProbeResult(ctx, ret, result, started) {
		t.Fatal("expected result delivery")
	}
	queued := <-ret
	event := <-events
	if event.Outcome != ProbeOpen || !event.Open {
		t.Fatalf("expected open event, got %#v", event)
	}
	if event.Result == nil || event.Result.Port != queued.Port {
		t.Fatalf("expected event result to match queued result, queued=%#v event=%#v", queued, event)
	}
	if event.Ext != "marker" {
		t.Fatalf("expected Ext marker, got %#v", event.Ext)
	}
	if event.StartedAt != started || event.FinishedAt.IsZero() {
		t.Fatalf("unexpected event timing: %#v", event)
	}
}

func TestEmitOpenProbeResultAbortsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ret := make(chan OpenIpPort, 1)
	events := make(chan ProbeEvent, 1)
	started := time.Now().Add(-time.Second)
	result := OpenIpPort{
		Ip:   net.ParseIP("127.0.0.1"),
		Port: 8080,
		IpOption: IpOption{
			OnProbeDone: func(event ProbeEvent) {
				events <- event
			},
		},
	}

	if EmitOpenProbeResult(ctx, ret, result, started) {
		t.Fatal("expected canceled context to reject result delivery")
	}
	select {
	case queued := <-ret:
		t.Fatalf("did not expect queued result after cancellation: %#v", queued)
	default:
	}
	event := <-events
	if event.Outcome != ProbeAborted || event.Open {
		t.Fatalf("expected aborted event, got %#v", event)
	}
}
