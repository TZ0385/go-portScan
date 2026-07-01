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

func TestTcpScannerWaitHostPacerStopsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	scanner := &TcpScanner{ctx: ctx, cancel: cancel}
	scanner.hostPacer = port.NewHostPacerStore(100, time.Minute, nil)
	scanner.hostPacer.Observe("127.0.0.1", port.HostSample{RTT: 200 * time.Millisecond, HasRTT: true})
	cancel()
	if err := scanner.waitHostPacer(net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("expected canceled context to stop host pacer wait")
	}
}

func TestTcpScannerHandleHostSampleUpdatesPacer(t *testing.T) {
	pacer := port.NewHostPacerStore(100, time.Minute, time.Now)
	scanner := &TcpScanner{hostPacer: pacer}
	scanner.observeHostSample("127.0.0.1", port.HostSample{RTT: 200 * time.Millisecond, HasRTT: true})
	delay := pacer.DebugSnapshot("127.0.0.1", time.Now()).NextDelay
	if delay <= 10*time.Millisecond {
		t.Fatalf("expected RTT sample to increase host pacing delay, got %s", delay)
	}
}

func TestTcpScannerSuccessfulDialUpdatesHostPacing(t *testing.T) {
	listener, portNum := startTCPTestListener(t)
	defer listener.Close()

	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{Rate: 100, RatePreHost: 100, Timeout: 500})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	targetIP := net.ParseIP("127.0.0.1")
	if err := scanner.Scan(targetIP, portNum, port.IpOption{}); err != nil {
		t.Fatal(err)
	}
	scanner.Wait()

	delay := scanner.hostPacer.DebugSnapshot(targetIP.String(), time.Now()).NextDelay
	if delay <= 0 {
		t.Fatalf("expected successful dial to create host pacing delay, got %s", delay)
	}
}

func TestTcpScannerFailedDialDoesNotUpdateHostPacing(t *testing.T) {
	retChan := make(chan port.OpenIpPort, 1)
	scanner, err := NewTcpScanner(retChan, port.ScannerOption{Rate: 100, RatePreHost: 100, Timeout: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer scanner.Close()

	targetIP := net.ParseIP("203.0.113.1")
	_ = scanner.Scan(targetIP, 65000, port.IpOption{})
	scanner.Wait()

	delay := scanner.hostPacer.DebugSnapshot(targetIP.String(), time.Now()).NextDelay
	if delay != 0 {
		t.Fatalf("expected failed dial not to change host pacing, got %s", delay)
	}
}

func TestTcpScannerHostPacingDoesNotReplaceFixedHostLimiter(t *testing.T) {
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
