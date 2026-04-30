package tcp

import (
	"github.com/XinRoom/go-portScan/core/port"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

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

func TestTcpScannerRawScanIsNotProbeLimited(t *testing.T) {
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

	for i := 0; i < cap(scanner.probe); i++ {
		scanner.probe <- struct{}{}
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
		t.Fatal("raw tcp scan was blocked by probe concurrency")
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

func TestTcpScannerCloseCancelsBlockedProbeAcquire(t *testing.T) {
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

	for i := 0; i < cap(scanner.probe); i++ {
		scanner.probe <- struct{}{}
	}

	if err := scanner.Scan(net.ParseIP("127.0.0.1"), uint16(portNum), port.IpOption{Httpx: true}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		scanner.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not unblock blocked probe acquisition")
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
