package fingerprint

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestPortIdentifyHTTP(t *testing.T) {
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
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}()
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

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), uint16(portNum), time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "http" {
		t.Fatalf("got service %q with banner %q, want http", service, string(banner))
	}
}

func TestIdentifyBudget(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "default", timeout: 0, want: 2 * time.Second},
		{name: "minimum", timeout: 250 * time.Millisecond, want: 2 * time.Second},
		{name: "scaled", timeout: time.Second, want: 4 * time.Second},
		{name: "maximum", timeout: 3 * time.Second, want: 8 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := identifyBudget(tt.timeout); got != tt.want {
				t.Fatalf("identifyBudget(%s) = %s, want %s", tt.timeout, got, tt.want)
			}
		})
	}
}

func TestRemainingTimeout(t *testing.T) {
	deadline := time.Now().Add(100 * time.Millisecond)
	got, ok := remainingTimeout(deadline, time.Second)
	if !ok {
		t.Fatal("expected remaining timeout")
	}
	if got <= 0 || got > 100*time.Millisecond {
		t.Fatalf("unexpected remaining timeout %s", got)
	}

	_, ok = remainingTimeout(time.Now().Add(-time.Millisecond), time.Second)
	if ok {
		t.Fatal("expected expired deadline")
	}
}

func Example_identifyBudget() {
	fmt.Println(identifyBudget(500 * time.Millisecond))
	// Output: 2s
}
