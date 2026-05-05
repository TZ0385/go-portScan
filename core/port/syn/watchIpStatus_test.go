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

func TestWatchIpStatusTableRecordAndClose(t *testing.T) {
	table := newWatchIpStatusTable(800 * time.Millisecond)
	defer table.Close()

	table.CreateOrUpdateLastTime("127.0.0.1", port.IpOption{FingerPrint: true})
	table.RecordPort("127.0.0.1", 80)

	if !table.HasPort("127.0.0.1", 80) {
		t.Fatal("expected recorded port")
	}
	ipOption, ok := table.GetIpOption("127.0.0.1")
	if !ok {
		t.Fatal("expected ip option")
	}
	if !ipOption.FingerPrint {
		t.Fatal("expected stored ip option")
	}

	table.Close()
	if !table.IsEmpty() {
		t.Fatal("expected close to clear ip status table")
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
	w.CreateOrUpdateLastTime("127.0.0.1", port.IpOption{})
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
