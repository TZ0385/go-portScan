package fingerprint

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint/webfinger"
	"github.com/XinRoom/go-portScan/util"
	"github.com/XinRoom/go-portScan/util/httputil"
)

var httpsTopPort = []uint16{443, 4443, 1443, 8443}

var httpClients sync.Map

func getHTTPClient(dialTimeout time.Duration) *http.Client {
	if v, ok := httpClients.Load(dialTimeout); ok {
		return v.(*http.Client)
	}
	// Keep one client per timeout bucket so short and long probes do not trample each other's budgets.
	client := httputil.NewHttpClient(dialTimeout)
	actual, _ := httpClients.LoadOrStore(dialTimeout, client)
	return actual.(*http.Client)
}

func ProbeHttpInfo(host string, _port uint16, topScheme string, dialTimeout time.Duration) (httpInfo *port.HttpInfo, banner []byte, isDialErr bool) {
	var schemes []string

	if util.IsUint16InList(_port, httpsTopPort) || topScheme == "https" {
		schemes = []string{"https", "http"}
	} else {
		schemes = []string{"http", "https"}
	}

	var url2 string

	for _, scheme := range schemes {
		url2 = fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, strconv.Itoa(int(_port))))

		var httpInfo2 *port.HttpInfo
		var banner2 []byte
		httpInfo2, banner2, isDialErr = WebHttpInfo(url2, dialTimeout, true)
		if isDialErr {
			return
		}

		if httpInfo2 != nil {
			httpInfo = httpInfo2
			banner = banner2
			if httpInfo2.StatusCode != 400 {
				break
			}
		}
	}

	return
}

func WebHttpInfo(url2 string, dialTimeout time.Duration, favicon bool) (httpInfo *port.HttpInfo, banner []byte, isDialErr bool) {
	httpClient := getHTTPClient(dialTimeout)

	var err error
	var body []byte
	var resps []*http.Response

	var b bytes.Buffer
	defer b.Reset()

	resps, body, err = getReq(httpClient, url2, 1)
	if err != nil {
		if isDialOrTimeoutErr(err) {
			return nil, banner, true
		}
	}
	if len(resps) > 0 {
		resp := resps[len(resps)-1]
		for i := len(resps) - 1; i >= 0; i-- {
			if resps[i] != nil && resps[i].StatusCode == 200 && resps[i].Body != nil {
				body, _ = httputil.GetBody(resps[i])
				resps[i].Body = io.NopCloser(bytes.NewReader(body))
				resp = resps[i]
				break
			}
		}
		b.Reset()
		resp.Write(&b)
		resp.Body = io.NopCloser(bytes.NewReader(body))
		banner = b.Bytes()
		//
		httpInfo = new(port.HttpInfo)
		httpInfo.Url = resp.Request.URL.String()
		httpInfo.StatusCode = resp.StatusCode
		httpInfo.ContentLen = int(resp.ContentLength)
		httpInfo.RemoteAddr = resp.Request.RemoteAddr
		rewriteUrl, err := resp.Location()
		if err == nil {
			httpInfo.Location = rewriteUrl.String()
		}
		httpInfo.Server = resp.Header.Get("Server")
		httpInfo.Title = ExtractTitle(body)
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			httpInfo.TlsCN = resp.TLS.PeerCertificates[0].Subject.CommonName
			httpInfo.TlsDNS = resp.TLS.PeerCertificates[0].DNSNames
		}
		// finger
		for i := 0; i < len(resps); i++ {
			httpInfo.Fingers = append(httpInfo.Fingers, webfinger.WebFingerIdent(resps[i])...)
		}
		// favicon
		if favicon {
			fau := webfinger.FindFaviconUrl(string(banner))
			if fau == "" {
				fau = "/favicon.ico"
			}
			faviconURL, err := resolveURL(resp.Request.URL, fau)
			if err != nil {
				return
			}
			resps2, body2, err2 := getReq(httpClient, faviconURL, 0)
			if err2 == nil && len(body2) != 0 && len(resps2) > 0 && resps2[0].StatusCode == 200 && strings.Contains(resps2[0].Header.Get("Content-Type"), "image") {
				httpInfo.Favicon = body2
				httpInfo.FaviconHash = webfinger.WebFaviconHash(body2)
				httpInfo.Fingers = append(httpInfo.Fingers, webfinger.WebFingerIdentByFavicon(httpInfo.FaviconHash)...)
			}
		}
	}
	return
}

func isDialOrTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	// Probe callers treat connect/timeout failures as "enrichment unavailable" and preserve the open port.
	errText := strings.ToLower(err.Error())
	return (errors.As(err, &netErr) && netErr.Timeout()) ||
		strings.Contains(errText, "timeout") ||
		strings.Contains(errText, refusedStr)
}

func resolveURL(base *url.URL, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(u).String(), nil
}

func traceRemoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}

func getReq(httpClient *http.Client, url2 string, maxRewriteNum int) (resps []*http.Response, body []byte, err error) {
	var rewriteNum int
	var req *http.Request
	for {
		var resp *http.Response
		var connectAddr string
		trace := &httptrace.ClientTrace{
			ConnectStart: func(net, addr string) {
				connectAddr = traceRemoteHost(addr)
			},
		}
		req, err = http.NewRequest(http.MethodGet, url2, http.NoBody)
		if err != nil {
			return
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Close = true // disable keepalive
		resp, err = httpClient.Do(req)
		if err != nil {
			if rewriteNum != 0 {
				err = nil
			}
			return
		}
		resp.Request.RemoteAddr = connectAddr
		resps = append(resps, resp)
		if resp.Body != http.NoBody && resp.Body != nil {
			body, err = httputil.GetBody(resp)
			if err != nil && err != httputil.ErrOverflow {
				return
			}
			if contentTypes, _ := resp.Header["Content-Type"]; len(contentTypes) > 0 {
				if strings.Contains(contentTypes[0], "text") {
					_body, err2 := DecodeData(body, resp.Header)
					if err2 == nil {
						body = _body
					}
				}
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
		if resp.ContentLength == -1 {
			resp.ContentLength = int64(len(body))
		}

		var rewriteUrl string
		rewriteUrl2, _ := resp.Location()
		if rewriteUrl2 != nil {
			rewriteUrl = rewriteUrl2.String()
		} else {
			rewriteUrl = GetLocation(body)
		}
		if rewriteUrl != "" && rewriteNum < maxRewriteNum {
			if !strings.HasPrefix(rewriteUrl, "http") {
				if strings.HasPrefix(rewriteUrl, "/") {
					resp.Request.URL.Path = rewriteUrl
				} else {
					resp.Request.URL.Path = resp.Request.URL.Path[:strings.LastIndex(resp.Request.URL.Path, "/")+1] + rewriteUrl
				}
				rewriteUrl = resp.Request.URL.String()
			}
			if rewriteUrl == url2 {
				break
			}
			url2 = rewriteUrl
			rewriteNum++
		} else {
			break
		}
	}
	return
}
