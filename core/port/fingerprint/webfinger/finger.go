package webfinger

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// ref:https://github.com/EdgeSecurityTeam/EHole/blob/main/finger.json

type Date struct {
	Name     string
	Location string
	Method   string
	Keyword  []string
	Or       bool

	compiledRegex []*regexp.Regexp
}

type WebFinger struct {
	Name    string
	Fingers []Date
}

var WebFingers []WebFinger

var onceLoadFingers sync.Once
var loadedWebFingers atomic.Value
var webFingersConfigured atomic.Bool
var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

//go:embed finger.json
var DefFingerData []byte

// LoadWebFingerData 加载web指纹数据
func LoadWebFingerData(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	err = ParseWebFingerData(data)
	if err != nil {
		return err
	}
	return nil
}

func ParseWebFingerData(data []byte) error {
	var parsed []WebFinger
	err := json.Unmarshal(data, &parsed)
	if err != nil {
		return err
	}
	err = normalizeWebFingers(parsed)
	if err != nil {
		return err
	}
	WebFingers = parsed
	loadedWebFingers.Store(parsed)
	webFingersConfigured.Store(true)
	return nil
}

func normalizeWebFingers(fingers []WebFinger) error {
	for i := range fingers {
		for j := range fingers[i].Fingers {
			finger := &fingers[i].Fingers[j]
			if finger.Location == "header" {
				for k := range finger.Keyword {
					finger.Keyword[k] = strings.ToLower(finger.Keyword[k])
				}
			}
			if finger.Method == "regular" {
				compiled, err := compileRegularKeywords(finger.Keyword)
				if err != nil {
					return err
				}
				finger.compiledRegex = compiled
			}
		}
	}
	return nil
}

func compileRegularKeywords(keywords []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(keywords))
	for _, keyword := range keywords {
		re, err := regexp.Compile(keyword)
		if err != nil {
			return nil, fmt.Errorf("compile web fingerprint regex %q: %w", keyword, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func getWebFingers() []WebFinger {
	v := loadedWebFingers.Load()
	if v == nil {
		return nil
	}
	return v.([]WebFinger)
}

func ensureWebFingersLoaded() {
	if webFingersConfigured.Load() {
		return
	}
	onceLoadFingers.Do(func() {
		if webFingersConfigured.Load() {
			return
		}
		if err := ParseWebFingerData(DefFingerData); err != nil {
			panic(fmt.Sprintf("load embedded web fingerprints: %v", err))
		}
	})
}

// WebFingerIdent web系统指纹识别
func WebFingerIdent(resp *http.Response) (names []string) {
	ensureWebFingersLoaded()
	webFingers := getWebFingers()
	if len(webFingers) == 0 {
		return nil
	}
	var dataMap = make(map[string]string)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	dataMap["body"] = string(body)
	dataMap["title"] = extractTitleText(body)
	var b bytes.Buffer
	resp.Header.Write(&b)
	dataMap["header"] = strings.ToLower(b.String())
	for _, finger := range webFingers {
		for _, finger2 := range finger.Fingers {
			var flag bool
			if _, ok := dataMap[finger2.Location]; !ok {
				continue
			}
			switch finger2.Method {
			case "keyword":
				if iskeyword(dataMap[finger2.Location], finger2.Keyword, finger2.Or) {
					flag = true
				}
			case "regular":
				if isregular(dataMap[finger2.Location], finger2) {
					flag = true
				}
			}
			if flag {
				matchedName := finger.Name
				if finger2.Name != "" {
					matchedName += "," + finger2.Name
				}
				names = append(names, matchedName)
				break
			}
		}
	}
	return
}

func extractTitleText(body []byte) string {
	matches := titlePattern.FindSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(string(matches[1]))
}

// WebFingerIdentByFavicon web系统指纹识别,通过Favicon.ico
func WebFingerIdentByFavicon(hash string) (names []string) {
	ensureWebFingersLoaded()
	webFingers := getWebFingers()
	if len(webFingers) == 0 {
		return nil
	}
	for _, finger := range webFingers {
		for _, finger2 := range finger.Fingers {
			switch finger2.Method {
			case "faviconhash":
				if hash != "" && len(finger2.Keyword) > 0 && hash == finger2.Keyword[0] {
					matchedName := finger.Name
					if finger2.Name != "" {
						matchedName += "," + finger2.Name
					}
					names = append(names, matchedName)
					break
				}
			}
		}
	}
	return
}

func WebFaviconHash(body []byte) string {
	return mmh3Hash32(standBase64(body))
}
