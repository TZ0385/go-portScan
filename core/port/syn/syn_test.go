//go:build !nosyn

package syn

import (
	"context"
	"errors"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type cancelOnWaitHostLimiter struct {
	cancel context.CancelFunc
}

type stubSerializeBuffer struct {
	data []byte
}

func (b *stubSerializeBuffer) Bytes() []byte { return b.data }
func (b *stubSerializeBuffer) Clear()        { b.data = nil }
func (b *stubSerializeBuffer) PrependBytes(n int) ([]byte, error) {
	b.data = make([]byte, n)
	return b.data, nil
}
func (b *stubSerializeBuffer) AppendBytes(n int) ([]byte, error) {
	start := len(b.data)
	b.data = append(b.data, make([]byte, n)...)
	return b.data[start:], nil
}

func (l *cancelOnWaitHostLimiter) Wait(_ context.Context, _ string) error {
	if l.cancel != nil {
		l.cancel()
	}
	return nil
}

func TestSynScannerWaitHostLimiterIsCanceledByClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ss := &SynScanner{
		ctx:          ctx,
		cancel:       cancel,
		hostLimiter:  newHostLimiter(1),
		openPortChan: make(chan synOpenProbe, 1),
		retChan:      make(chan port.OpenIpPort, 1),
	}

	if err := ss.waitHostLimiter(net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("expected first same-host wait to pass, got %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- ss.waitHostLimiter(net.ParseIP("127.0.0.1"))
	}()

	select {
	case err := <-result:
		t.Fatalf("expected second same-host wait to block before close, got %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	ss.Close()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected close to cancel blocked same-host wait")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected blocked same-host wait to exit after close")
	}
}

func TestSynScannerCloseDoesNotCloseResultChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	retChan := make(chan port.OpenIpPort, 1)
	ss := &SynScanner{
		ctx:          ctx,
		cancel:       cancel,
		openPortChan: make(chan synOpenProbe, 1),
		retChan:      retChan,
	}

	ss.Close()

	select {
	case _, ok := <-retChan:
		if !ok {
			t.Fatal("expected caller-owned result channel to remain open")
		}
	default:
	}
	close(retChan)
}

func TestSynScannerScanBlocksOnHostLimiterUntilClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ss := &SynScanner{
		ctx:            ctx,
		cancel:         cancel,
		hostLimiter:    newHostLimiter(1),
		watchIpStatusT: newWatchIpStatusTable(time.Second),
		openPortChan:   make(chan synOpenProbe, 1),
		retChan:        make(chan port.OpenIpPort, 1),
	}
	t.Cleanup(ss.Close)

	ip := net.ParseIP("127.0.0.1")
	if err := ss.waitHostLimiter(ip); err != nil {
		t.Fatalf("expected first same-host wait to pass, got %v", err)
	}

	result := make(chan error, 1)
	go func() {
		result <- ss.Scan(ip, 80, port.IpOption{})
	}()

	select {
	case err := <-result:
		t.Fatalf("expected Scan to block on same-host limiter before close, got %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	if !ss.watchIpStatusT.IsEmpty() {
		t.Fatal("expected blocked Scan to stop before watch state is updated")
	}

	ss.Close()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("expected Close to cancel blocked Scan")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected blocked Scan to exit after close")
	}

	if !ss.watchIpStatusT.IsEmpty() {
		t.Fatal("expected canceled Scan to exit before packet preparation state changes")
	}
}

func TestSynScannerScanStopsWhenContextCanceledAfterHostLimiterWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ip := net.ParseIP("127.0.0.1")
	watchIpStatusT := newWatchIpStatusTable(time.Second)
	watchMacCacheT := newWatchMacCacheTable()
	watchMacCacheT.UpdateLastTime(ip.String())

	ss := &SynScanner{
		ctx:            ctx,
		hostLimiter:    &cancelOnWaitHostLimiter{cancel: cancel},
		watchIpStatusT: watchIpStatusT,
		watchMacCacheT: watchMacCacheT,
		openPortChan:   make(chan synOpenProbe, 1),
		retChan:        make(chan port.OpenIpPort, 1),
		cancel:         cancel,
	}
	t.Cleanup(ss.Close)

	err := ss.Scan(ip, 80, port.IpOption{FingerPrint: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
	if !watchIpStatusT.IsEmpty() {
		t.Fatal("expected canceled Scan to stop before watch state is updated")
	}
}

func TestSynScannerScanRejectsInvalidTargetBeforeNetworkWork(t *testing.T) {
	ss := &SynScanner{ctx: context.Background()}
	for _, target := range []struct {
		ip   net.IP
		port uint16
	}{
		{ip: nil, port: 80},
		{ip: net.IP{1, 2, 3}, port: 80},
		{ip: net.ParseIP("192.0.2.10"), port: 0},
	} {
		if err := ss.Scan(target.ip, target.port, port.IpOption{}); err == nil {
			t.Fatalf("target ip=%v port=%d should be rejected", target.ip, target.port)
		}
	}
}

func TestSynScannerFixedHostLimiterRemainsActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss := &SynScanner{
		ctx:         ctx,
		cancel:      cancel,
		hostLimiter: newHostLimiter(1),
	}
	if err := ss.waitHostLimiter(net.ParseIP("127.0.0.1")); err != nil {
		t.Fatalf("expected first host limiter wait to pass, got %v", err)
	}
	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer blockedCancel()
	if err := ss.hostLimiter.Wait(blockedCtx, "127.0.0.1"); err == nil {
		t.Fatal("expected fixed host limiter to remain active")
	}
}

func TestSynScannerGetHwAddrV6StopsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ss := &SynScanner{
		ctx:            ctx,
		cancel:         cancel,
		watchMacCacheT: newWatchMacCacheTable(),
		openPortChan:   make(chan synOpenProbe),
		retChan:        make(chan port.OpenIpPort),
	}
	t.Cleanup(ss.Close)

	result := make(chan error, 1)
	go func() {
		_, err := ss.getHwAddrV6(net.ParseIP("2001:db8::1"))
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation error, got %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected getHwAddrV6 to stop promptly after context cancellation")
	}
}

func TestSynScannerGetHwAddrV6TimesOutWithoutNeighborReply(t *testing.T) {
	ss := &SynScanner{
		ctx:            context.Background(),
		option:         port.ScannerOption{Timeout: 50},
		srcMac:         net.HardwareAddr{0, 1, 2, 3, 4, 5},
		srcIp:          net.ParseIP("fe80::1"),
		watchMacCacheT: newWatchMacCacheTable(),
		bufPool: &sync.Pool{New: func() interface{} {
			return gopacket.NewSerializeBuffer()
		}},
	}
	defer ss.watchMacCacheT.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected timeout before send path panic, got panic: %v", r)
		}
	}()

	start := time.Now()
	_, err := ss.getHwAddrV6(net.ParseIP("2001:db8::1"))
	if err == nil || err.Error() != "timeout getting ICMP V6 NA reply" {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("expected prompt timeout, got %s", elapsed)
	}
}

func TestSynRecvBPFFilterIncludesRequiredResponses(t *testing.T) {
	filter := synRecvBPFFilter(net.HardwareAddr{0, 1, 2, 3, 4, 5})
	if !strings.Contains(filter, "tcp-rst") && !strings.Contains(filter, "0x04") {
		t.Fatalf("expected filter to include RST capture, got %q", filter)
	}
	if !strings.Contains(filter, "tcp-syn|tcp-ack") && !strings.Contains(filter, "0x12") {
		t.Fatalf("expected filter to include SYN+ACK capture, got %q", filter)
	}
	if !strings.Contains(filter, "ip6[40] = 136") {
		t.Fatalf("expected filter to include ICMPv6 neighbor advertisements, got %q", filter)
	}
}

func TestSynScannerSendFailureEmitsProbeError(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	events := make(chan port.ProbeEvent, 1)
	ss := &SynScanner{
		ctx:            context.Background(),
		watchIpStatusT: newWatchIpStatusTable(time.Second),
		watchMacCacheT: newWatchMacCacheTable(),
		bufPool: &sync.Pool{New: func() interface{} {
			return &stubSerializeBuffer{}
		}},
		opts:         gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		srcMac:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		srcIp:        net.ParseIP("127.0.0.2").To4(),
		srcIp6:       net.ParseIP("::1"),
		gwMac:        net.HardwareAddr{6, 7, 8, 9, 10, 11},
		openPortChan: make(chan synOpenProbe, 1),
		retChan:      make(chan port.OpenIpPort, 1),
	}
	ss.watchMacCacheT.UpdateLastTime(ip.String())
	ss.watchMacCacheT.SetMac(ip.String(), net.HardwareAddr{6, 7, 8, 9, 10, 11})
	ss.sendPacket = func(...gopacket.SerializableLayer) error {
		return errors.New("send failed")
	}
	defer ss.watchIpStatusT.Close()
	defer ss.watchMacCacheT.Close()

	err := ss.Scan(ip, 80, port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})
	if err == nil || err.Error() != "send failed" {
		t.Fatalf("expected send failed error, got %v", err)
	}

	select {
	case event := <-events:
		if event.Outcome != port.ProbeError || event.Err == nil {
			t.Fatalf("expected probe error event, got %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("expected probe error event")
	}
	if !ss.watchIpStatusT.IsEmpty() {
		t.Fatal("expected failed send to leave no pending watch state")
	}
}

func TestSynScannerOpenProbeEmitsOpenEventAfterResultQueued(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ret := make(chan port.OpenIpPort, 1)
	events := make(chan port.ProbeEvent, 1)
	ss := &SynScanner{
		ctx:          ctx,
		cancel:       cancel,
		openPortChan: make(chan synOpenProbe, 1),
		retChan:      ret,
	}
	ss.probeLoopWg.Add(1)
	go func() {
		defer ss.probeLoopWg.Done()
		ss.portProbeHandle()
	}()
	defer ss.Close()

	if !ss.enqueueOpenPort(synOpenProbe{
		result: port.OpenIpPort{
			Ip:   net.ParseIP("127.0.0.1"),
			Port: 80,
			IpOption: port.IpOption{
				Ext:         "syn-open",
				OnProbeDone: func(event port.ProbeEvent) { events <- event },
			},
		},
		probe: pendingProbe{
			startedAt: time.Now().Add(-time.Millisecond),
		},
	}) {
		t.Fatal("expected enqueue to succeed")
	}

	result := <-ret
	event := <-events
	if !event.Open || event.Outcome != port.ProbeOpen {
		t.Fatalf("expected open event, got %#v", event)
	}
	if event.Result == nil || event.Result.Port != result.Port {
		t.Fatalf("expected event result to reference queued result, got result=%#v event=%#v", result, event)
	}
	if event.Ext != "syn-open" {
		t.Fatalf("expected Ext to propagate, got %#v", event.Ext)
	}
}

func TestSynScannerCanceledOpenProbeEmitsAbortedEventWithoutResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ret := make(chan port.OpenIpPort)
	events := make(chan port.ProbeEvent, 1)
	ss := &SynScanner{
		ctx:          ctx,
		cancel:       cancel,
		openPortChan: make(chan synOpenProbe, 1),
		retChan:      ret,
	}
	ss.probeLoopWg.Add(1)
	go func() {
		defer ss.probeLoopWg.Done()
		ss.portProbeHandle()
	}()
	defer ss.Close()

	if !ss.enqueueOpenPort(synOpenProbe{
		result: port.OpenIpPort{
			Ip:   net.ParseIP("127.0.0.1"),
			Port: 80,
			IpOption: port.IpOption{
				OnProbeDone: func(event port.ProbeEvent) { events <- event },
			},
		},
		probe: pendingProbe{
			startedAt: time.Now().Add(-time.Millisecond),
		},
	}) {
		t.Fatal("expected enqueue to succeed")
	}

	cancel()

	select {
	case event := <-events:
		if event.Outcome != port.ProbeAborted || event.Open {
			t.Fatalf("expected aborted event, got %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("expected canceled open probe to emit aborted event")
	}

	select {
	case result := <-ret:
		t.Fatalf("canceled open probe should not emit result: %#v", result)
	default:
	}
}

func TestSynScannerWaitLetsConfiguredTimeoutCompletePendingProbe(t *testing.T) {
	timeout := 2200 * time.Millisecond
	events := make(chan port.ProbeEvent, 2)
	ctx, cancel := context.WithCancel(context.Background())
	ss := &SynScanner{
		ctx:            ctx,
		cancel:         cancel,
		option:         port.ScannerOption{Timeout: int(timeout / time.Millisecond)},
		watchIpStatusT: newWatchIpStatusTable(timeout),
		openPortChan:   make(chan synOpenProbe),
		retChan:        make(chan port.OpenIpPort),
	}

	ss.watchIpStatusT.RecordSentProbe("192.0.2.10", 49152, 443, time.Now(), port.IpOption{
		OnProbeDone: func(event port.ProbeEvent) { events <- event },
	})

	ss.Wait()
	ss.Close()

	select {
	case event := <-events:
		if event.Outcome != port.ProbeNoResponse {
			t.Fatalf("expected normal wait to finish as no response, got %#v", event)
		}
	default:
		t.Fatal("expected wait to emit a no-response event before close")
	}
	select {
	case event := <-events:
		t.Fatalf("expected exactly one terminal event, got extra %#v", event)
	default:
	}
}

func TestSynScannerWaitBlocksUntilOpenProbeResultIsConsumed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ret := make(chan port.OpenIpPort)
	ss := &SynScanner{
		ctx:          ctx,
		cancel:       cancel,
		openPortChan: make(chan synOpenProbe, 1),
		retChan:      ret,
	}
	ss.probeLoopWg.Add(1)
	go func() {
		defer ss.probeLoopWg.Done()
		ss.portProbeHandle()
	}()
	defer ss.Close()

	if !ss.enqueueOpenPort(synOpenProbe{result: port.OpenIpPort{Ip: net.ParseIP("127.0.0.1"), Port: 80}}) {
		t.Fatal("expected enqueue to succeed")
	}

	waited := make(chan struct{})
	go func() {
		ss.Wait()
		close(waited)
	}()

	select {
	case <-waited:
		t.Fatal("Wait returned after the channel was drained but before the probe task completed")
	case <-time.After(50 * time.Millisecond):
	}

	select {
	case result := <-ret:
		if result.Port != 80 {
			t.Fatalf("expected queued result to be delivered, got %#v", result)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected blocked probe result to be consumable")
	}

	select {
	case <-waited:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Wait did not return after the open probe result was consumed")
	}
}

type failingBPFFilterHandle struct {
	closed bool
}

func (h *failingBPFFilterHandle) SetBPFFilter(string) error {
	return errors.New("bad bpf")
}

func (h *failingBPFFilterHandle) Close() {
	h.closed = true
}

func TestConfigureSynRecvFilterClosesHandleOnError(t *testing.T) {
	handle := &failingBPFFilterHandle{}
	err := configureSynRecvFilter(handle, net.HardwareAddr{0, 1, 2, 3, 4, 5})
	if err == nil {
		t.Fatal("expected bpf filter error")
	}
	if !handle.closed {
		t.Fatal("expected failed filter setup to close handle")
	}
}

func TestNewSynScannerRejectsNonPositiveTimeout(t *testing.T) {
	for _, timeout := range []int{0, -1} {
		_, err := NewSynScanner(net.ParseIP("192.0.2.1"), make(chan port.OpenIpPort), port.ScannerOption{
			Rate:    100,
			Timeout: timeout,
		})
		if err == nil {
			t.Fatalf("timeout=%d should be rejected before opening pcap", timeout)
		}
	}
}

func TestSynScannerCachesIPv6NeighborAdvertisementByTargetAddress(t *testing.T) {
	table := newWatchMacCacheTable()
	defer table.Close()
	target := net.ParseIP("2001:db8::10")
	mac := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	table.UpdateLastTime(target.String())

	ss := &SynScanner{watchMacCacheT: table}
	ss.cacheIPv6NeighborAdvertisement(target, mac)

	if got := table.GetMac(target.String()); got == nil || got.String() != mac.String() {
		t.Fatalf("IPv6 neighbor MAC = %v, want %v", got, mac)
	}
}

func TestSynRecvParserDecodesIPv6NeighborAdvertisement(t *testing.T) {
	sourceMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	target := net.ParseIP("2001:db8::10")
	ipv6 := layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      net.ParseIP("fe80::1"),
		DstIP:      net.ParseIP("ff02::1"),
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	icmpv6.SetNetworkLayerForChecksum(&ipv6)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: sourceMAC, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv6},
		&ipv6,
		&icmpv6,
		&layers.ICMPv6NeighborAdvertisement{TargetAddress: target},
	); err != nil {
		t.Fatal(err)
	}

	var eth layers.Ethernet
	var decodedIPv6 layers.IPv6
	var decodedICMPv6 layers.ICMPv6
	var decodedNA layers.ICMPv6NeighborAdvertisement
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &decodedIPv6, &decodedICMPv6, &decodedNA)
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decodedNA.TargetAddress == nil || !decodedNA.TargetAddress.Equal(target) {
		t.Fatalf("decoded NA target = %v, want %v", decodedNA.TargetAddress, target)
	}
}
