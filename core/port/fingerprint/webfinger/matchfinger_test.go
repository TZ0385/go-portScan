package webfinger

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestIsKeywordShortASCIIRespectsBoundaries(t *testing.T) {
	if iskeyword("forums", []string{"rums"}, false) {
		t.Fatal("short ASCII keyword should not match inside a larger word")
	}

	for _, str := range []string{" rums ", "(rums)", "rums(科创站群管理平台)"} {
		if !iskeyword(str, []string{"rums"}, false) {
			t.Fatalf("short ASCII keyword should match at boundary: %q", str)
		}
	}
}

func TestIsKeywordPreservesContainsForUnicodeAndLongerKeywords(t *testing.T) {
	if !iskeyword("超科创站群管理平台", []string{"科创"}, false) {
		t.Fatal("unicode keywords should keep substring matching")
	}

	if !iskeyword("xxadminyy", []string{"admin"}, false) {
		t.Fatal("longer ASCII keywords should keep substring matching")
	}
}

func TestFindFaviconURLParsesRelTokens(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "quoted icon",
			body: `<html><head><link rel="icon" href="/favicon.ico"></head></html>`,
			want: "/favicon.ico",
		},
		{
			name: "unquoted icon",
			body: `<html><head><link rel=icon href=/favicon.ico></head></html>`,
			want: "/favicon.ico",
		},
		{
			name: "shortcut icon",
			body: `<html><head><link href="/shortcut.ico" rel="shortcut icon"></head></html>`,
			want: "/shortcut.ico",
		},
		{
			name: "prefer normal icon over apple touch icon",
			body: `<link rel="apple-touch-icon" href="/apple.png"><link rel="icon" href="/favicon.ico">`,
			want: "/favicon.ico",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FindFaviconUrl(tt.body); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWebFingerIdentRestoresResponseBody(t *testing.T) {
	resp, err := http.ReadResponse(
		bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>body-marker</body></html>")),
		&http.Request{Method: http.MethodGet},
	)
	if err != nil {
		t.Fatalf("build response: %v", err)
	}
	defer resp.Body.Close()

	_ = WebFingerIdent(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !strings.Contains(string(body), "body-marker") {
		t.Fatalf("expected response body to be restored, got %q", string(body))
	}
}

func TestWebFingerIdentClosesOriginalResponseBody(t *testing.T) {
	body := &closeTrackingReadCloser{Reader: strings.NewReader("<html><body>body-marker</body></html>")}
	resp := &http.Response{
		Header: make(http.Header),
		Body:   body,
	}

	_ = WebFingerIdent(resp)

	if !body.closed {
		t.Fatal("expected original response body to be closed")
	}
}

func TestWebFingerIdentDoesNotReloadDefaultsAfterExplicitEmptyConfig(t *testing.T) {
	resetWebFingerLoaderForTest(t, []byte(`[
  {
    "name": "DefaultOnly",
    "fingers": [
      { "location": "body", "method": "keyword", "keyword": ["body-marker"] }
    ]
  }
]`))

	if err := ParseWebFingerData([]byte(`[]`)); err != nil {
		t.Fatalf("parse explicit empty config: %v", err)
	}

	names := WebFingerIdent(&http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader("<html><body>body-marker</body></html>")),
	})
	if len(names) != 0 {
		t.Fatalf("expected explicit empty config to stay empty, got %v", names)
	}
}

func TestWebFingerIdentPanicsOnInvalidEmbeddedFingerData(t *testing.T) {
	resetWebFingerLoaderForTest(t, []byte(`[
  {
    "name": "Broken",
    "fingers": [
      { "location": "body", "method": "regular", "keyword": ["("] }
    ]
  }
]`))

	defer func() {
		if recover() == nil {
			t.Fatal("expected invalid embedded finger data to fail fast")
		}
	}()

	_ = WebFingerIdent(&http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader("<html></html>")),
	})
}

func TestWebFingerIdentMatchesRegularRule(t *testing.T) {
	data := []byte(`[
  {
    "name": "AScanRegular",
    "fingers": [
      { "location": "body", "method": "regular", "keyword": ["a.+b"] }
    ]
  }
]`)

	if err := ParseWebFingerData(data); err != nil {
		t.Fatalf("parse web finger data: %v", err)
	}

	names := WebFingerIdent(&http.Response{
		Header: make(http.Header),
		Body:   io.NopCloser(strings.NewReader("<html><body>axb</body></html>")),
	})
	if len(names) != 1 || names[0] != "AScanRegular" {
		t.Fatalf("expected regular rule to match body, got %v", names)
	}
}

func TestParseWebFingerDataRejectsInvalidRegularMatcher(t *testing.T) {
	data := []byte(`[
  {
    "name": "AScanInvalidRegular",
    "fingers": [
      { "location": "body", "method": "regular", "keyword": ["("] }
    ]
  }
]`)

	if err := ParseWebFingerData(data); err == nil {
		t.Fatal("expected invalid regular matcher to return an error")
	}
}

func TestDefaultFingerDataRegularMatchersCompile(t *testing.T) {
	if err := ParseWebFingerData(DefFingerData); err != nil {
		t.Fatalf("default finger data should parse: %v", err)
	}
}

func TestDefaultFingerDataUsesCanonicalFaviconHashSchema(t *testing.T) {
	var rules []WebFinger
	if err := json.Unmarshal(DefFingerData, &rules); err != nil {
		t.Fatalf("unmarshal default finger data: %v", err)
	}
	for _, rule := range rules {
		for _, matcher := range rule.Fingers {
			if matcher.Method != "faviconhash" {
				continue
			}
			if matcher.Location != "favicon" {
				t.Fatalf("faviconhash matcher must use location=favicon, got rule=%q location=%q", rule.Name, matcher.Location)
			}
		}
	}
}

type closeTrackingReadCloser struct {
	*strings.Reader
	closed bool
}

func (c *closeTrackingReadCloser) Close() error {
	c.closed = true
	return nil
}

func resetWebFingerLoaderForTest(t *testing.T, defaultData []byte) {
	t.Helper()
	savedDef := append([]byte(nil), DefFingerData...)
	t.Cleanup(func() {
		DefFingerData = savedDef
		clearWebFingerLoaderState()
		if err := ParseWebFingerData(savedDef); err != nil {
			t.Fatalf("restore default finger data: %v", err)
		}
	})

	DefFingerData = append([]byte(nil), defaultData...)
	clearWebFingerLoaderState()
}

func clearWebFingerLoaderState() {
	onceLoadFingers = sync.Once{}
	loadedWebFingers = atomic.Value{}
	WebFingers = nil
	webFingersConfigured.Store(false)
}
