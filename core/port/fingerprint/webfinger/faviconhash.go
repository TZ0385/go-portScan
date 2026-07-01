package webfinger

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/twmb/murmur3"
	"golang.org/x/net/html"
)

func FindFaviconUrl(body string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return ""
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if !strings.EqualFold(token.Data, "link") {
				continue
			}

			var rel, href string
			for _, attr := range token.Attr {
				switch strings.ToLower(attr.Key) {
				case "rel":
					rel = attr.Val
				case "href":
					href = attr.Val
				}
			}
			if href == "" {
				continue
			}

			relTokens := strings.Fields(strings.ToLower(rel))
			hasIcon := false
			hasApple := false
			for _, relToken := range relTokens {
				if relToken == "icon" {
					hasIcon = true
				}
				if relToken == "apple-touch-icon" || relToken == "apple-touch-icon-precomposed" {
					hasApple = true
				}
			}
			if hasIcon && !hasApple {
				return href
			}
		}
	}
}

func mmh3Hash32(raw []byte) string {
	var h32 = murmur3.New32()
	_, err := h32.Write(raw)
	if err == nil {
		return fmt.Sprintf("%d", int32(h32.Sum32()))
	} else {
		return ""
	}
}

func standBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
