package webfinger

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
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
}

type WebFinger struct {
	Name    string
	Fingers []Date
}

var WebFingers []WebFinger

var onceLoadFingers sync.Once
var loadedWebFingers atomic.Value

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
	normalizeWebFingers(parsed)
	WebFingers = parsed
	loadedWebFingers.Store(parsed)
	return nil
}

func normalizeWebFingers(fingers []WebFinger) {
	for i := range fingers {
		for j := range fingers[i].Fingers {
			if fingers[i].Fingers[j].Location != "header" {
				continue
			}
			for k := range fingers[i].Fingers[j].Keyword {
				fingers[i].Fingers[j].Keyword[k] = strings.ToLower(fingers[i].Fingers[j].Keyword[k])
			}
		}
	}
}

func getWebFingers() []WebFinger {
	v := loadedWebFingers.Load()
	if v == nil {
		return nil
	}
	return v.([]WebFinger)
}

func ensureWebFingersLoaded() {
	onceLoadFingers.Do(func() {
		if len(getWebFingers()) == 0 {
			_ = ParseWebFingerData(DefFingerData)
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
	dataMap["body"] = string(body)
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
				if isregular(dataMap[finger2.Location], finger2.Keyword, finger2.Or) {
					flag = true
				}
			}
			if flag {
				if finger2.Name != "" {
					finger.Name += "," + finger2.Name
				}
				names = append(names, finger.Name)
				break
			}
		}
	}
	return
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
					if finger2.Name != "" {
						finger.Name += "," + finger2.Name
					}
					names = append(names, finger.Name)
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
