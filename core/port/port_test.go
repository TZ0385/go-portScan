package port

import "testing"

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
