package main

import (
	"flag"
	"testing"

	"github.com/urfave/cli/v2"
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
