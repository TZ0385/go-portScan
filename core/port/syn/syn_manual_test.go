//go:build manual && !nosyn

package syn

import (
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/iprange"
	"github.com/panjf2000/ants/v2"
)

// TestSynScannerScanIntegration 会使用真实网卡和公网目标，只能通过 manual 门禁主动执行。
func TestSynScannerScanIntegration(t *testing.T) {
	done := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	go func() {
		for ret := range retChan {
			log.Println(ret)
		}
		close(done)
	}()

	ports, err := port.ShuffleParseAndMergeTopPorts("top1000")
	if err != nil {
		t.Fatal(err)
	}
	it, startIP, _ := iprange.NewIter("1.1.1.1/30")
	ss, err := NewSynScanner(startIP, retChan, DefaultSynOption)
	if err != nil {
		t.Fatal(err)
	}

	portScan := func(ip net.IP) {
		for _, dstPort := range ports {
			if err := ss.WaitLimiter(); err != nil {
				return
			}
			_ = ss.Scan(ip, dstPort, port.IpOption{})
		}
	}

	var wgPing sync.WaitGroup
	poolPing, _ := ants.NewPoolWithFunc(50, func(ip interface{}) {
		defer wgPing.Done()
		target := ip.(net.IP)
		if host.IsLive(target.String(), true, 800*time.Millisecond) {
			portScan(target)
		}
	})
	defer poolPing.Release()

	start := time.Now()
	for i := uint64(0); i < it.TotalNum(); i++ {
		ip := make(net.IP, len(it.GetIpByIndex(0)))
		copy(ip, it.GetIpByIndex(i))
		wgPing.Add(1)
		poolPing.Invoke(ip)
	}

	wgPing.Wait()
	ss.Wait()
	ss.Close()
	// scanner 不拥有结果通道；手工测试必须由调用方关闭，才能等待消费者退出。
	close(retChan)
	<-done
	t.Log(time.Since(start))
}
