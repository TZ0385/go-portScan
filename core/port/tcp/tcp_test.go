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
