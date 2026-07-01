package main

import (
	"flag"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/urfave/cli/v2"
	"io"
	"log"
	"net"
	"sync"
	"testing"
)

func TestParseFlagBuildsScannerOptionWithRatePreHost(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Int("rate", 120, "")
	_ = fs.Int("miniRate", 60, "")
	_ = fs.Int("timeout", 800, "")
	_ = fs.String("nexthop", "", "")
	_ = fs.Bool("debug", false, "")
	_ = fs.Int("ratePreHost", 7, "")
	if err := fs.Parse([]string{"--ratePreHost=7", "--rate=120", "--miniRate=60", "--timeout=800"}); err != nil {
		t.Fatal(err)
	}

	ctx := cli.NewContext(nil, fs, nil)
	parseFlag(ctx)
	option := scannerOptionFromFlags()

	if option.RatePreHost != 7 {
		t.Fatalf("expected RatePreHost 7, got %d", option.RatePreHost)
	}
	if option.Rate != 120 {
		t.Fatalf("expected Rate 120, got %d", option.Rate)
	}
	if option.MiniRate != 60 {
		t.Fatalf("expected MiniRate 60, got %d", option.MiniRate)
	}
	if option.Timeout != 800 {
		t.Fatalf("expected Timeout 800, got %d", option.Timeout)
	}
	if option.Debug {
		t.Fatal("expected Debug false")
	}
	if option.NextHop != "" {
		t.Fatalf("expected empty NextHop, got %q", option.NextHop)
	}
}

func TestConsumeResultDoesNotEmitProbeLifecycleEvent(t *testing.T) {
	oldMaxOpenPort := maxOpenPort
	oldOJson := oJson
	maxOpenPort = 0
	oJson = false
	t.Cleanup(func() {
		maxOpenPort = oldMaxOpenPort
		oJson = oldOJson
	})

	events := make(chan port.ProbeEvent, 1)
	ret := port.OpenIpPort{
		Ip:   net.ParseIP("127.0.0.1"),
		Port: 80,
		IpOption: port.IpOption{
			OnProbeDone: func(event port.ProbeEvent) { events <- event },
		},
	}

	consumeResult(ret, log.New(io.Discard, "", 0), nil, nil, &sync.RWMutex{}, map[string]int{})

	select {
	case event := <-events:
		t.Fatalf("result consumer should not emit lifecycle event: %#v", event)
	default:
	}
}
