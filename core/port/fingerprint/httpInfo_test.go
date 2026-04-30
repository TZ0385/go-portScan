package fingerprint

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebHttpInfoFaviconRelativeURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><link rel="shortcut icon" href="/favicon.ico"></head><title>ok</title></html>`))
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write([]byte("ico"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	info, _, isDialErr := WebHttpInfo(server.URL, time.Second, true)
	if isDialErr {
		t.Fatal("expected local server to be reachable")
	}
	if info == nil {
		t.Fatal("expected http info")
	}
	if len(info.Favicon) == 0 {
		t.Fatal("expected favicon body from relative favicon url")
	}
}
