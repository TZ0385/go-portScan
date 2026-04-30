package httputil

import (
	"testing"
	"time"
)

func TestNewHttpClientTimeoutScalesWithDialTimeout(t *testing.T) {
	client := NewHttpClient(2800 * time.Millisecond)
	if client.Timeout < 6*time.Second {
		t.Fatalf("expected request timeout to scale with dial timeout, got %s", client.Timeout)
	}
}

func TestNewHttpClientKeepsMinimumTimeout(t *testing.T) {
	client := NewHttpClient(800 * time.Millisecond)
	if client.Timeout != 3*time.Second {
		t.Fatalf("expected minimum request timeout 3s, got %s", client.Timeout)
	}
}
