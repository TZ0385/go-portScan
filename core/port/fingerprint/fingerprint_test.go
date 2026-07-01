package fingerprint

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestPortIdentifyHTTP(t *testing.T) {
	portNum := startFingerprintTestListener(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), portNum, time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "http" {
		t.Fatalf("got service %q with banner %q, want http", service, string(banner))
	}
}

func TestPortIdentifySlowSSHBanner(t *testing.T) {
	portNum := startFingerprintTestListener(t, func(conn net.Conn) {
		time.Sleep(700 * time.Millisecond)
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
	})

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), portNum, time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "ssh" {
		t.Fatalf("got service %q with banner %q, want ssh", service, string(banner))
	}
}

func TestPortIdentifySlowHTTPResponse(t *testing.T) {
	portNum := startFingerprintTestListener(t, func(conn net.Conn) {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), portNum, time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "http" {
		t.Fatalf("got service %q with banner %q, want http", service, string(banner))
	}
}

func TestPortIdentifySplitHTTPResponse(t *testing.T) {
	portNum := startFingerprintTestListener(t, func(conn net.Conn) {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP"))
		time.Sleep(100 * time.Millisecond)
		_, _ = conn.Write([]byte("/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), portNum, time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "http" {
		t.Fatalf("got service %q with banner %q, want http", service, string(banner))
	}
}

func TestPortIdentifyHTTP400FallbackReturnsHTTPS(t *testing.T) {
	cert := testTLSCertificate(t)
	var connCount atomic.Int32
	portNum := startFingerprintTestListener(t, func(conn net.Conn) {
		if connCount.Add(1) <= 2 {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}

		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := bufio.NewReader(tlsConn).ReadString('\n'); err != nil {
			return
		}
		_, _ = tlsConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), portNum, time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "https" {
		t.Fatalf("got service %q with banner %q, want https", service, string(banner))
	}
}

func startFingerprintTestListener(t *testing.T, handler func(net.Conn)) uint16 {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				handler(conn)
			}(conn)
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
	return uint16(portNum)
}

func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestDamengFingerprintRule(t *testing.T) {
	services, ok := portServiceOrder[5236]
	if !ok || len(services) == 0 || services[0] != "dameng" {
		t.Fatalf("expected port 5236 to prefer dameng, got %v", services)
	}
	rule, ok := serviceRules["dameng"]
	if !ok {
		t.Fatal("expected dameng service rule")
	}
	if len(rule.DataGroup) != 2 {
		t.Fatalf("expected dameng rule to send probe then read response, got %d steps", len(rule.DataGroup))
	}
	if rule.DataGroup[0].Action != ActionSend || len(rule.DataGroup[0].Data) == 0 {
		t.Fatal("expected dameng first step to send a probe")
	}
	if rule.DataGroup[1].Action != ActionRecv || len(rule.DataGroup[1].Regexps) == 0 {
		t.Fatal("expected dameng second step to match a response")
	}
	if !matchRuleWhithBuf([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x00, 0x02}, net.ParseIP("127.0.0.1"), 5236, rule.DataGroup[1]) {
		t.Fatal("expected dameng response marker 00 00 00 00 e4 00 to match")
	}
	if !matchRuleWhithBuf([]byte{0x02, 0x40, 0x00, 0x00, 0x00, 0x03}, net.ParseIP("127.0.0.1"), 5236, rule.DataGroup[1]) {
		t.Fatal("expected dameng response marker 40 00 00 00 to match")
	}
}

func TestPortIdentifyDameng(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0xe4, 0x00, 0x02})
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	oldServices, hadServices := portServiceOrder[uint16(portNum)]
	portServiceOrder[uint16(portNum)] = []string{"dameng"}
	t.Cleanup(func() {
		if hadServices {
			portServiceOrder[uint16(portNum)] = oldServices
			return
		}
		delete(portServiceOrder, uint16(portNum))
	})

	service, banner, isDialErr := PortIdentify("tcp", net.ParseIP("127.0.0.1"), uint16(portNum), time.Second)
	if isDialErr {
		t.Fatal("expected local listener to be reachable")
	}
	if service != "dameng" {
		t.Fatalf("got service %q with banner %q, want dameng", service, string(banner))
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
