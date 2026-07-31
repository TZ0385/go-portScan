package tcp

import (
	"context"
	"errors"
	"github.com/XinRoom/go-portScan/core/port"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type cancelOnWaitHostLimiter struct {
	cancel context.CancelFunc
}

func (l *cancelOnWaitHostLimiter) Wait(_ context.Context, _ string) error {
	if l.cancel != nil {
		l.cancel()
	}
	return nil
}

func startTCPTestListener(t *testing.T) (net.Listener, uint16) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	return listener, uint16(portNum)
}

func TestTcpScanner_Scan(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:    100,
		Timeout: 200,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := scanner.Scan(net.ParseIP("127.0.0.1"), uint16(portNum), port.IpOption{}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-retChan:
		if got.Port != uint16(portNum) {
			t.Fatalf("got port %d, want %d", got.Port, portNum)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for open tcp port")
	}

	scanner.Wait()
}

func TestTcpScannerCloseIsIdempotent(t *testing.T) {
	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:    100,
		Timeout: 200,
	})
	if err != nil {
		t.Fatal(err)
	}

	scanner.Close()
	scanner.Close()

	if err := scanner.Scan(net.ParseIP("127.0.0.1"), 1, port.IpOption{}); err == nil {
		t.Fatal("expected scan after close to fail")
	}
}

func TestTcpScannerUsesSmallStableBurst(t *testing.T) {
	scanner, err := NewTcpScanner(make(chan port.OpenIpPort, 1), port.ScannerOption{Rate: 600, Timeout: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()
	if got := scanner.limiter.Burst(); got != 6 {
		t.Fatalf("limiter burst = %d, want 6", got)
	}
}

func TestTcpScannerFingerprintQueueFullStillEmitsUnknownOpenPort(t *testing.T) {
	listener, portNum := startTCPTestListener(t)
	defer listener.Close()

	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:              100,
		Timeout:           200,
		FingerTimeout:     200,
		FingerConcurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	if !scanner.fingerPool.TrySubmit(func() {
		close(started)
		<-release
	}) {
		t.Fatal("failed to occupy fingerprint worker")
	}
	<-started
	for i := 0; i < 4; i++ {
		if !scanner.fingerPool.TrySubmit(func() { <-release }) {
			t.Fatalf("failed to fill fingerprint queue at index %d", i)
		}
	}

	events := make(chan port.ProbeEvent, 2)
	if err := scanner.Scan(net.ParseIP("127.0.0.1"), portNum, port.IpOption{
		FingerPrint: true,
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-retChan:
		if result.Service != "unknown" {
			t.Fatalf("degraded service = %q, want unknown", result.Service)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for degraded open-port result")
	}
	select {
	case event := <-events:
		if event.Outcome != port.ProbeOpen {
			t.Fatalf("probe outcome = %v, want open", event.Outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for terminal probe event")
	}
	select {
	case event := <-events:
		t.Fatalf("unexpected duplicate terminal event: %+v", event)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	scanner.Close()
}

func TestTcpScannerFingerprintAndHTTPShareTotalBudget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn, index int32) {
				defer conn.Close()
				if index == 1 {
					_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
					return
				}
				time.Sleep(2 * time.Second)
			}(conn, accepted.Add(1))
		}
	}()
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{Rate: 100, Timeout: 200, FingerTimeout: 300})
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now()
	scanner.enrichAndEmit(context.Background(), port.OpenIpPort{
		Ip:       net.ParseIP("127.0.0.1"),
		Port:     uint16(portNumber),
		IpOption: port.IpOption{FingerPrint: true, Httpx: true},
	}, startedAt)
	if elapsed := time.Since(startedAt); elapsed > 700*time.Millisecond {
		t.Fatalf("combined fingerprint budget exceeded: %s", elapsed)
	}
	select {
	case <-retChan:
	default:
		t.Fatal("open port was lost after enrichment timeout")
	}
	scanner.Close()
}

func TestTcpScannerProbeContextCancelsWhileWaitingForCapacity(t *testing.T) {
	scanner, err := NewTcpScanner(make(chan port.OpenIpPort, 1), port.ScannerOption{
		Rate:          100,
		Timeout:       100,
		MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	scanner.inflight <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = scanner.ProbeContext(ctx, net.ParseIP("127.0.0.1"), 80, port.IpOption{})
	<-scanner.inflight
	scanner.Close()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ProbeContext error = %v, want context canceled", err)
	}
}

func TestTcpScannerCloseDoesNotCloseResultChannel(t *testing.T) {
	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:    100,
		Timeout: 200,
	})
	if err != nil {
		t.Fatal(err)
	}

	scanner.Close()

	select {
	case _, ok := <-retChan:
		if !ok {
			t.Fatal("expected caller-owned result channel to remain open")
		}
	default:
	}
	close(retChan)
}

func TestTcpScannerScanStopsWhenContextCanceledAfterHostLimiterWait(t *testing.T) {
	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:    100,
		Timeout: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scanner.Close)

	ctx, cancel := context.WithCancel(context.Background())
	scanner.ctx = ctx
	scanner.cancel = cancel
	scanner.hostLimiter = &cancelOnWaitHostLimiter{cancel: cancel}

	err = scanner.Scan(net.ParseIP("127.0.0.1"), 80, port.IpOption{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
}

func TestTcpScannerFixedHostLimiterRemainsActive(t *testing.T) {
	listener, portNum := startTCPTestListener(t)
	defer listener.Close()

	retChan := make(chan port.OpenIpPort, 2)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{Rate: 100, RatePreHost: 1, Timeout: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	targetIP := net.ParseIP("127.0.0.1")
	if err := scanner.Scan(targetIP, portNum, port.IpOption{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retChan:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first open tcp port")
	}

	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer blockedCancel()
	if err := scanner.hostLimiter.Wait(blockedCtx, targetIP.String()); err == nil {
		t.Fatal("expected fixed host limiter to remain active")
	}
}

func TestTcpScannerKeepsOpenPortWhenHTTPProbeTimesOut(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if accepted.Add(1) == 1 {
				_ = conn.Close()
				continue
			}
			time.Sleep(4 * time.Second)
			_ = conn.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:          100,
		Timeout:       200,
		FingerTimeout: 200,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := scanner.Scan(net.ParseIP("127.0.0.1"), uint16(portNum), port.IpOption{Httpx: true}); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-retChan:
		if got.Port != uint16(portNum) {
			t.Fatalf("got port %d, want %d", got.Port, portNum)
		}
		if got.HttpInfo != nil {
			t.Fatal("expected timed out http probe to keep open port without http info")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("timed out waiting for open port after http probe timeout")
	}

	scanner.Wait()
}

func TestTcpScannerScanThrottlesSameHostByRatePerHost(t *testing.T) {
	listener, portNum := startTCPTestListener(t)
	defer listener.Close()

	retChan := make(chan port.OpenIpPort, 2)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:        100,
		RatePreHost: 5,
		Timeout:     200,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	targetIP := net.ParseIP("127.0.0.1")
	if err := scanner.Scan(targetIP, portNum, port.IpOption{}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-retChan:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first open tcp port")
	}

	start := time.Now()
	if err := scanner.Scan(targetIP, portNum, port.IpOption{}); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 120*time.Millisecond {
		t.Fatalf("expected second same-host Scan call to block, returned after %v", elapsed)
	}

	select {
	case <-retChan:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for throttled same-host scan result")
	}
}

func TestTcpScannerCloseCancelsBlockedRatePerHostWait(t *testing.T) {
	listener, portNum := startTCPTestListener(t)
	defer listener.Close()

	retChan := make(chan port.OpenIpPort, 2)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{
		Rate:        100,
		RatePreHost: 1,
		Timeout:     200,
	})
	if err != nil {
		t.Fatal(err)
	}

	targetIP := net.ParseIP("127.0.0.1")
	if err := scanner.Scan(targetIP, portNum, port.IpOption{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retChan:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first open tcp port")
	}

	result := make(chan error, 1)
	go func() {
		result <- scanner.Scan(targetIP, portNum, port.IpOption{})
	}()

	select {
	case err := <-result:
		t.Fatalf("expected second same-host Scan call to stay blocked before close, got %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	closed := make(chan struct{})
	go func() {
		scanner.Close()
		close(closed)
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected blocked Scan call to exit with cancellation error")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected blocked Scan call to exit after close")
	}

	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected close to cancel blocked per-host wait")
	}
}

func TestTcpScannerClosedProbeEmitsClosedEvent(t *testing.T) {
	ret := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(ret, port.ScannerOption{Rate: 100, Timeout: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	events := make(chan port.ProbeEvent, 1)
	if err := scanner.Scan(net.ParseIP("127.0.0.1"), 1, port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	}); err != nil {
		t.Fatal(err)
	}
	scanner.Wait()

	select {
	case event := <-events:
		if event.Open || event.Outcome != port.ProbeClosed {
			t.Fatalf("expected closed event, got %#v", event)
		}
		if event.Port != 1 || !event.StartedAt.Before(event.FinishedAt) {
			t.Fatalf("unexpected event timing or port: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("closed probe did not emit event")
	}
	select {
	case result := <-ret:
		t.Fatalf("closed probe should not emit result: %#v", result)
	default:
	}
}

func TestTcpScannerOpenProbeEmitsOpenEventAfterResultQueued(t *testing.T) {
	listener, portNum := startTCPTestListener(t)
	defer listener.Close()

	ret := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(ret, port.ScannerOption{Rate: 100, Timeout: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	events := make(chan port.ProbeEvent, 1)
	if err := scanner.Scan(net.ParseIP("127.0.0.1"), portNum, port.IpOption{
		Ext:         "tcp-open",
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	}); err != nil {
		t.Fatal(err)
	}

	result := <-ret
	event := <-events
	if !event.Open || event.Outcome != port.ProbeOpen {
		t.Fatalf("expected open event, got %#v", event)
	}
	if event.Result == nil || event.Result.Port != result.Port {
		t.Fatalf("expected event result to reference queued result, got result=%#v event=%#v", result, event)
	}
	if event.Ext != "tcp-open" {
		t.Fatalf("expected Ext to propagate, got %#v", event.Ext)
	}
}
