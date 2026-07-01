//go:build !nosyn

package syn

import (
	"net"
	"testing"
	"time"

	"github.com/XinRoom/go-portScan/core/port"
)

func TestWatchMacCacheTable(t *testing.T) {
	table := newWatchMacCacheTable()
	defer table.Close()

	table.UpdateLastTime("127.0.0.1")
	if !table.IsNeedWatch("127.0.0.1") {
		t.Fatal("expected host without mac to require watch")
	}

	want := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	table.SetMac("127.0.0.1", want)
	if table.IsNeedWatch("127.0.0.1") {
		t.Fatal("expected host with mac to not require watch")
	}
	if got := table.GetMac("127.0.0.1"); got.String() != want.String() {
		t.Fatalf("got mac %s, want %s", got, want)
	}

	table.Close()
	if !table.IsEmpty() {
		t.Fatal("expected close to clear mac cache")
	}
}

func TestWatchTablesCloseIsIdempotent(t *testing.T) {
	macs := newWatchMacCacheTable()
	macs.Close()
	macs.Close()

	ips := newWatchIpStatusTable(time.Second)
	ips.Close()
	ips.Close()
}

func TestWatchIpStatusTimeoutReportsHostTimeout(t *testing.T) {
	timeoutCh := make(chan string, 1)
	w := newWatchIpStatusTable(20 * time.Millisecond)
	w.onHostTimeout = func(host string) {
		timeoutCh <- host
	}
	w.RecordSentProbe("127.0.0.1", 49152, 443, time.Now().Add(-time.Second), port.IpOption{})
	defer w.Close()
	select {
	case host := <-timeoutCh:
		if host != "127.0.0.1" {
			t.Fatalf("expected timeout host 127.0.0.1, got %s", host)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("expected timeout callback")
	}
}

func TestWatchIpStatusRejectsDuplicateProbeKey(t *testing.T) {
	w := newWatchIpStatusTable(time.Second)
	defer w.Close()

	key, ok := w.RecordSentProbe("192.0.2.10", 49152, 443, time.Now(), port.IpOption{})
	if !ok {
		t.Fatal("expected first probe to be recorded")
	}
	if key.srcPort != 49152 || key.dstPort != 443 {
		t.Fatalf("unexpected key: %#v", key)
	}
	if _, ok := w.RecordSentProbe("192.0.2.10", 49152, 443, time.Now(), port.IpOption{}); ok {
		t.Fatal("expected duplicate probe key to be rejected")
	}
}

func TestWatchIpStatusReserveProbeFindsOnlyFreeSourcePort(t *testing.T) {
	w := newWatchIpStatusTable(time.Minute)
	defer w.Close()

	for src := synSourcePortMin; src <= synSourcePortMax; src++ {
		if src == synSourcePortMax {
			continue
		}
		if _, ok := w.RecordSentProbe("192.0.2.10", src, 443, time.Now(), port.IpOption{}); !ok {
			t.Fatalf("record source port %d", src)
		}
	}

	key, probe, ok := w.ReserveProbe("192.0.2.10", 443, time.Now(), port.IpOption{Ext: "reserved"})
	if !ok {
		t.Fatal("expected reservation to find final free source port")
	}
	if key.srcPort != synSourcePortMax || probe.key != key || probe.option.Ext != "reserved" {
		t.Fatalf("unexpected reservation key=%#v probe=%#v", key, probe)
	}
}

func TestWatchIpStatusReserveProbeReportsExhaustionOnlyWhenFull(t *testing.T) {
	w := newWatchIpStatusTable(time.Minute)
	defer w.Close()

	for src := synSourcePortMin; src <= synSourcePortMax; src++ {
		if _, ok := w.RecordSentProbe("192.0.2.10", src, 443, time.Now(), port.IpOption{}); !ok {
			t.Fatalf("record source port %d", src)
		}
	}

	if key, probe, ok := w.ReserveProbe("192.0.2.10", 443, time.Now(), port.IpOption{}); ok {
		t.Fatalf("expected exhaustion, got key=%#v probe=%#v", key, probe)
	}
}

func TestWatchIpStatusReserveProbeWrapsSourcePortCursor(t *testing.T) {
	w := newWatchIpStatusTable(time.Minute)
	defer w.Close()

	w.nextSrcPort = synSourcePortMax

	key, _, ok := w.ReserveProbe("192.0.2.10", 443, time.Now(), port.IpOption{})
	if !ok || key.srcPort != synSourcePortMax {
		t.Fatalf("expected first reservation at max port, got key=%#v ok=%v", key, ok)
	}
	if w.nextSrcPort != synSourcePortMin {
		t.Fatalf("expected cursor to wrap to min, got %d", w.nextSrcPort)
	}

	key, _, ok = w.ReserveProbe("192.0.2.10", 443, time.Now(), port.IpOption{})
	if !ok || key.srcPort != synSourcePortMin {
		t.Fatalf("expected second reservation at min port, got key=%#v ok=%v", key, ok)
	}
}

func TestWatchIpStatusAllowsSameSourcePortForDifferentTargetPorts(t *testing.T) {
	w := newWatchIpStatusTable(time.Second)
	defer w.Close()

	if _, ok := w.RecordSentProbe("192.0.2.10", 49152, 443, time.Now(), port.IpOption{}); !ok {
		t.Fatal("expected first probe")
	}
	if _, ok := w.RecordSentProbe("192.0.2.10", 49152, 8443, time.Now(), port.IpOption{}); !ok {
		t.Fatal("same source port is unambiguous when destination port differs")
	}
	if _, ok := w.TakeProbe("192.0.2.10", 49152, 443); !ok {
		t.Fatal("expected first destination port to remain addressable")
	}
	if _, ok := w.TakeProbe("192.0.2.10", 49152, 8443); !ok {
		t.Fatal("expected second destination port to remain addressable")
	}
}

func TestWatchIpStatusIsEmptyAfterTakingLastProbe(t *testing.T) {
	w := newWatchIpStatusTable(time.Second)
	defer w.Close()

	if _, ok := w.RecordSentProbe("192.0.2.10", 49152, 443, time.Now(), port.IpOption{}); !ok {
		t.Fatal("expected probe to be recorded")
	}
	if _, ok := w.TakeProbe("192.0.2.10", 49152, 443); !ok {
		t.Fatal("expected probe to be taken")
	}
	if !w.IsEmpty() {
		t.Fatal("expected no pending probe state after taking last probe")
	}
}

func TestWatchIpStatusTimeoutCompletesEachExpiredProbe(t *testing.T) {
	events := make(chan port.ProbeEvent, 2)
	w := newWatchIpStatusTable(10 * time.Millisecond)
	defer w.Close()

	w.RecordSentProbe("192.0.2.10", 49152, 443, time.Now().Add(-time.Second), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})
	w.RecordSentProbe("192.0.2.10", 49153, 8443, time.Now().Add(-time.Second), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})

	got := map[uint16]port.ProbeOutcome{}
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case event := <-events:
			got[event.Port] = event.Outcome
		case <-deadline:
			t.Fatalf("timed out waiting for events, got %#v", got)
		}
	}
	if got[443] != port.ProbeNoResponse || got[8443] != port.ProbeNoResponse {
		t.Fatalf("unexpected timeout events: %#v", got)
	}
}

func TestWatchIpStatusTimeoutIsPerProbeNotPerHost(t *testing.T) {
	events := make(chan port.ProbeEvent, 2)
	w := newWatchIpStatusTable(1500 * time.Millisecond)
	defer w.Close()

	oldSentAt := time.Now().Add(-2 * time.Second)
	newSentAt := time.Now()
	w.RecordSentProbe("192.0.2.10", 49152, 443, oldSentAt, port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})
	w.RecordSentProbe("192.0.2.10", 49153, 8443, newSentAt, port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})

	select {
	case event := <-events:
		if event.Port != 443 || event.Outcome != port.ProbeNoResponse {
			t.Fatalf("expected only old probe to time out first, got %#v", event)
		}
	case <-time.After(1300 * time.Millisecond):
		t.Fatal("expected old probe to time out independently")
	}
	select {
	case event := <-events:
		t.Fatalf("newer probe should still be pending, got %#v", event)
	default:
	}
	if _, ok := w.TakeProbe("192.0.2.10", 49153, 8443); !ok {
		t.Fatal("expected newer probe to remain pending")
	}
}

func TestWatchIpStatusCloseAbortsPendingProbes(t *testing.T) {
	events := make(chan port.ProbeEvent, 1)
	w := newWatchIpStatusTable(time.Second)
	w.RecordSentProbe("192.0.2.10", 49152, 443, time.Now(), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})

	w.Close()

	select {
	case event := <-events:
		if event.Outcome != port.ProbeAborted {
			t.Fatalf("expected aborted event, got %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("expected aborted event")
	}
}
