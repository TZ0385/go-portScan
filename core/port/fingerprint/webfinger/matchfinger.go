package webfinger

import "strings"

func iskeyword(str string, keyword []string, or bool) bool {
	if len(keyword) == 0 || str == "" {
		return false
	}
	for _, k := range keyword {
		b := containsKeyword(str, k)
		if !or && !b {
			return false
		}
		if or && b {
			return true
		}
	}
	return !or
}

func containsKeyword(str string, keyword string) bool {
	if !shouldUseBoundaryMatch(keyword) {
		return strings.Contains(str, keyword)
	}

	// Short ASCII keywords such as rums/cms/oa are noisy with plain substring
	// matching. Require ASCII alnum boundaries while preserving legacy behavior
	// for longer or non-ASCII keywords.
	for start := 0; start < len(str); {
		idx := strings.Index(str[start:], keyword)
		if idx == -1 {
			return false
		}
		idx += start
		end := idx + len(keyword)
		if isASCIIAlphaNumBoundary(str, idx-1) && isASCIIAlphaNumBoundary(str, end) {
			return true
		}
		start = idx + 1
	}

	return false
}

func shouldUseBoundaryMatch(keyword string) bool {
	if len(keyword) == 0 || len(keyword) > 4 {
		return false
	}
	for i := 0; i < len(keyword); i++ {
		if !isASCIIAlphaNum(keyword[i]) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumBoundary(str string, idx int) bool {
	if idx < 0 || idx >= len(str) {
		return true
	}
	return !isASCIIAlphaNum(str[idx])
}

func isASCIIAlphaNum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isregular(str string, matcher Date) bool {
	if len(matcher.Keyword) == 0 || str == "" || len(matcher.compiledRegex) == 0 {
		return false
	}
	for _, re := range matcher.compiledRegex {
		b := re.MatchString(str)
		if !matcher.Or && !b {
			return false
		}
		if matcher.Or && b {
			return true
		}
	}
	return !matcher.Or
}
