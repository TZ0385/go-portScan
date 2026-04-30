package port

import "testing"

func TestProbeConcurrencyBounds(t *testing.T) {
	tests := []struct {
		name string
		rate int
		want int
	}{
		{name: "default", rate: 0, want: DefaultProbeConcurrency},
		{name: "minimum", rate: 10, want: MinProbeConcurrency},
		{name: "scaled", rate: 800, want: 80},
		{name: "maximum", rate: 10000, want: MaxProbeConcurrency},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProbeConcurrency(tt.rate); got != tt.want {
				t.Fatalf("ProbeConcurrency(%d) = %d, want %d", tt.rate, got, tt.want)
			}
		})
	}
}

func TestNormalizeMiniRate(t *testing.T) {
	if got := NormalizeMiniRate(600, 300); got != 300 {
		t.Fatalf("expected mini rate 300, got %d", got)
	}
	if got := NormalizeMiniRate(100, 300); got != 100 {
		t.Fatalf("expected mini rate clamped to rate, got %d", got)
	}
	if got := NormalizeMiniRate(100, 0); got != 0 {
		t.Fatalf("expected zero mini rate unchanged, got %d", got)
	}
}

func TestFingerTimeout(t *testing.T) {
	if got := FingerTimeout(800, 0); got != 2000 {
		t.Fatalf("expected default finger timeout 2000ms, got %d", got)
	}
	if got := FingerTimeout(2800, 0); got != 2800 {
		t.Fatalf("expected scanner timeout to be reused when large enough, got %d", got)
	}
	if got := FingerTimeout(800, 3000); got != 3000 {
		t.Fatalf("expected explicit finger timeout, got %d", got)
	}
}

func TestProbeRate(t *testing.T) {
	if got := ProbeRate(0, 0); got != DefaultProbeRate {
		t.Fatalf("expected default probe rate %d, got %d", DefaultProbeRate, got)
	}
	if got := ProbeRate(600, 0); got != 120 {
		t.Fatalf("expected derived probe rate 120, got %d", got)
	}
	if got := ProbeRate(10, 0); got != MinProbeRate {
		t.Fatalf("expected min probe rate %d, got %d", MinProbeRate, got)
	}
	if got := ProbeRate(10000, 0); got != MaxProbeRate {
		t.Fatalf("expected max probe rate %d, got %d", MaxProbeRate, got)
	}
	if got := ProbeRate(600, 7); got != 7 {
		t.Fatalf("expected explicit probe rate 7, got %d", got)
	}
	if got := ProbeRate(600, 9999); got != MaxProbeRate {
		t.Fatalf("expected explicit probe rate capped at %d, got %d", MaxProbeRate, got)
	}
}

func TestProbeLimiterBurst(t *testing.T) {
	if got := ProbeLimiterBurst(0); got != 1 {
		t.Fatalf("expected burst 1, got %d", got)
	}
	if got := ProbeLimiterBurst(9); got != 1 {
		t.Fatalf("expected burst 1, got %d", got)
	}
	if got := ProbeLimiterBurst(120); got != 12 {
		t.Fatalf("expected burst 12, got %d", got)
	}
}
