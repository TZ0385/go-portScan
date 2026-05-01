package syn

import (
	"context"
	"errors"
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/iprange"
	"github.com/panjf2000/ants/v2"
	"log"
	"net"
	"os"
	"sync"
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

func TestSynScannerWaitHostLimiterIsCanceledByClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ss := &SynScanner{
		ctx:          ctx,
		cancel:       cancel,
		hostLimiter:  newHostLimiter(1),
		openPortChan: make(chan port.OpenIpPort, 1),
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
		openPortChan: make(chan port.OpenIpPort, 1),
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
		openPortChan:   make(chan port.OpenIpPort, 1),
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
		openPortChan:   make(chan port.OpenIpPort, 1),
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

func TestSynScannerGetHwAddrV6StopsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ss := &SynScanner{
		ctx:            ctx,
		cancel:         cancel,
		watchMacCacheT: newWatchMacCacheTable(),
		openPortChan:   make(chan port.OpenIpPort),
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

func TestSynScannerScanIntegration(t *testing.T) {
	if os.Getenv("GO_PORTSCAN_RUN_SYN_INTEGRATION") != "1" {
		t.Skip("set GO_PORTSCAN_RUN_SYN_INTEGRATION=1 to run SYN scanner integration test")
	}

	single := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	go func() {
		for ret := range retChan {
			log.Println(ret)
		}
		single <- struct{}{}
	}()

	// 解析端口字符串并且优先发送 TopTcpPorts 中的端口, eg: 1-65535,top1000
	ports, err := port.ShuffleParseAndMergeTopPorts("top1000")
	if err != nil {
		t.Fatal(err)
	}

	// parse ip
	it, startIp, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := NewSynScanner(startIp, retChan, DefaultSynOption)
	if err != nil {
		t.Fatal(err)
	}

	// port scan func
	portScan := func(ip net.IP) {
		for _, _port := range ports { // port
			ss.WaitLimiter()
			ss.Scan(ip, _port, port.IpOption{}) // syn 不能并发，默认以网卡和驱动最高性能发包
		}
	}

	// Pool - ping and port scan
	var wgPing sync.WaitGroup
	poolPing, _ := ants.NewPoolWithFunc(50, func(ip interface{}) {
		_ip := ip.(net.IP)
		if host.IsLive(_ip.String(), true, 800*time.Millisecond) {
			portScan(_ip)
		}
		wgPing.Done()
	})
	defer poolPing.Release()

	start := time.Now()
	for i := uint64(0); i < it.TotalNum(); i++ { // ip索引
		ip := make(net.IP, len(it.GetIpByIndex(0)))
		copy(ip, it.GetIpByIndex(i)) // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
		wgPing.Add(1)
		poolPing.Invoke(ip)
	}

	wgPing.Wait()
	ss.Wait()
	ss.Close()
	<-single
	t.Log(time.Since(start))
}
