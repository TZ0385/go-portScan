package fingerprint

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Action uint8

const (
	ActionRecv = Action(iota)
	ActionSend
)

const (
	refusedStr   = "refused"
	ioTimeoutStr = "i/o timeout"
)

const readIdleTimeout = 500 * time.Millisecond

type ruleData struct {
	Action  Action // send or recv
	Data    []byte // send or match data
	Regexps []*regexp.Regexp
}

type serviceRule struct {
	Tls       bool
	DataGroup []ruleData
}

var serviceRules = make(map[string]serviceRule)
var readBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 16*1024)
	},
}

type deadlineReader interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}

func identifyBudget(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 2 * time.Second
	}
	return timeout
}

func remainingTimeout(deadline time.Time, timeout time.Duration) (time.Duration, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, false
	}
	const maxAttempt = time.Second
	if timeout <= 0 || timeout > maxAttempt {
		timeout = maxAttempt
	}
	if remaining < timeout {
		return remaining, true
	}
	return timeout, true
}

// PortIdentify 端口识别
func PortIdentify(network string, ip net.IP, _port uint16, dailTimeout time.Duration) (serviceName string, banner []byte, isDialErr bool) {
	return PortIdentifyContext(context.Background(), network, ip, _port, dailTimeout)
}

func PortIdentifyContext(ctx context.Context, network string, ip net.IP, _port uint16, dailTimeout time.Duration) (serviceName string, banner []byte, isDialErr bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.Now().Add(identifyBudget(dailTimeout))

	matchedRule := make(map[string]struct{})
	// 记录对应服务已经进行过匹配
	recordMatched := func(s string) {
		matchedRule[s] = struct{}{}
		if gf, ok := groupFlows[s]; ok {
			for _, s2 := range gf {
				matchedRule[s2] = struct{}{}
			}
		}
	}

	unknown := "unknown"
	var sn string

	defer func() {
		if sn == "http" && bytes.HasPrefix(banner, []byte("HTTP/1.1 400")) {
			attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
			if !ok {
				return
			}
			sn2, banner2, isDialErr2 := matchRule(ctx, network, ip, _port, "https", attemptTimeout)
			if !isDialErr2 && sn2 != "" {
				sn = sn2
				serviceName = sn2
				banner = banner2
				isDialErr = isDialErr2
			}
		}
	}()

	// 优先判断port可能的服务
	if serviceNames, ok := portServiceOrder[_port]; ok {
		for _, service := range serviceNames {
			if ctx.Err() != nil {
				return unknown, banner, true
			}
			attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
			if !ok {
				return unknown, banner, false
			}
			recordMatched(service)
			sn, banner, isDialErr = matchRule(ctx, network, ip, _port, service, attemptTimeout)
			if sn != "" {
				return sn, banner, false
			} else if isDialErr {
				return unknown, banner, isDialErr
			}
		}
	}

	// onlyRecv
	{
		var conn net.Conn
		var n int
		var matchedService string
		buf := readBufPool.Get().([]byte)
		defer func() {
			readBufPool.Put(buf)
		}()
		address := net.JoinHostPort(ip.String(), strconv.Itoa(int(_port)))
		attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
		if !ok {
			return unknown, banner, false
		}
		conn, _ = (&net.Dialer{Timeout: attemptTimeout}).DialContext(ctx, network, address)
		if conn == nil {
			return unknown, banner, true
		}
		stopCancel := closeConnOnCancel(ctx, conn)
		attemptTimeout, ok = remainingTimeout(deadline, dailTimeout)
		if !ok {
			conn.Close()
			return unknown, banner, false
		}
		n, _ = readUntil(conn, buf, attemptTimeout, func(current []byte) bool {
			for _, service := range onlyRecv {
				if _, ok := matchedRule[service]; ok {
					continue
				}
				for _, rule := range serviceRules[service].DataGroup {
					if matchRuleWhithBuf(current, ip, _port, rule) {
						matchedService = service
						return true
					}
				}
			}
			return false
		})
		conn.Close()
		stopCancel()
		if n != 0 {
			banner = make([]byte, n)
			copy(banner, buf[:n])
			if matchedService != "" {
				return matchedService, banner, false
			}
			for _, service := range onlyRecv {
				recordMatched(service)
			}
		}
	}

	// 优先判断Top服务
	for _, service := range serviceOrder {
		if ctx.Err() != nil {
			return unknown, banner, true
		}
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
		if !ok {
			return unknown, banner, false
		}
		recordMatched(service)
		sn, banner, isDialErr = matchRule(ctx, network, ip, _port, service, attemptTimeout)
		if sn != "" {
			return sn, banner, false
		} else if isDialErr {
			return unknown, banner, true
		}
	}

	// other
	for _, service := range serviceRuleOrder {
		if ctx.Err() != nil {
			return unknown, banner, true
		}
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
		if !ok {
			return unknown, banner, false
		}
		sn, banner, isDialErr = matchRule(ctx, network, ip, _port, service, attemptTimeout)
		if sn != "" {
			return sn, banner, false
		} else if isDialErr {
			return unknown, banner, true
		}
	}

	return unknown, banner, false
}

// 指纹匹配函数
func matchRuleWhithBuf(buf, ip net.IP, _port uint16, rule ruleData) bool {
	data := []byte("")
	// 逐个判断
	//for _, rule := range serviceRule.DataGroup {
	if rule.Data != nil {
		data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
		data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
	}
	// 包含数据就正确
	if rule.Regexps != nil {
		for _, _regex := range rule.Regexps {
			if _regex.MatchString(convert2utf8(string(buf))) {
				return true
			}
		}
	}
	if bytes.Compare(data, []byte("")) != 0 && bytes.Contains(buf, data) {
		return true
	}
	return false
}

// 指纹匹配函数
func matchRule(ctx context.Context, network string, ip net.IP, _port uint16, serviceName string, dailTimeout time.Duration) (serviceNameRet string, banner []byte, isDialErr bool) {
	var err error
	var isTls bool
	var conn net.Conn
	var connTls *tls.Conn

	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(_port)))

	serviceRule2 := serviceRules[serviceName]
	flowsService := groupFlows[serviceName]

	// 建立连接
	if serviceRule2.Tls {
		conn, err = (&net.Dialer{Timeout: dailTimeout}).DialContext(ctx, network, address)
		if err == nil {
			connTls = tls.Client(conn, &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			})
			err = connTls.HandshakeContext(ctx)
		}
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			if strings.HasSuffix(err.Error(), ioTimeoutStr) || strings.Contains(err.Error(), refusedStr) {
				isDialErr = true
				return
			}
			var oe *net.OpError
			if errors.As(err, &oe) && oe.Op == "remote error" && reflect.TypeOf(oe.Err).Name() == "alert" {
				serviceNameRet = "tls"
			}
			return
		}
		defer connTls.Close()
		stopCancel := closeConnOnCancel(ctx, connTls)
		defer stopCancel()
		isTls = true
	} else {
		conn, err = (&net.Dialer{Timeout: dailTimeout}).DialContext(ctx, network, address)
		if conn == nil {
			isDialErr = true
			return
		}
		defer conn.Close()
		stopCancel := closeConnOnCancel(ctx, conn)
		defer stopCancel()
	}

	buf := readBufPool.Get().([]byte)
	defer func() {
		readBufPool.Put(buf)
	}()

	data := []byte("")
	// 逐个判断
	for _, rule := range serviceRule2.DataGroup {
		if rule.Data != nil {
			data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
			data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
		}

		if rule.Action == ActionSend {
			if isTls {
				connTls.SetWriteDeadline(time.Now().Add(dailTimeout))
				_, err = connTls.Write(data)
			} else {
				conn.SetWriteDeadline(time.Now().Add(dailTimeout))
				_, err = conn.Write(data)
			}
			if err != nil {
				// 出错就退出
				return
			}
		} else {
			var n int
			var matchedService string
			matcher := func(current []byte) bool {
				if matchRuleWhithBuf(current, ip, _port, rule) {
					matchedService = serviceName
					return true
				}
				// 可归并的服务规则组
				for _, s := range flowsService {
					for _, rule2 := range serviceRules[s].DataGroup {
						if rule2.Action == ActionSend {
							continue
						}
						if matchRuleWhithBuf(current, ip, _port, rule2) {
							matchedService = s
							return true
						}
					}
				}
				return false
			}
			if isTls {
				n, err = readUntil(connTls, buf, dailTimeout, matcher)
			} else {
				n, err = readUntil(conn, buf, dailTimeout, matcher)
			}
			// 出错就退出
			if n == 0 {
				return
			}
			banner = make([]byte, n)
			copy(banner, buf[:n])
			if matchedService != "" {
				serviceNameRet = matchedService
				return
			}
		}
	}

	// 兜底数据匹配
	if serviceNameRet == "" && len(banner) > 0 {
		for serviceName, _regex := range doneRecvFinger {
			if _regex.MatchString(convert2utf8(string(banner))) {
				serviceNameRet = serviceName
			}
		}
	}

	return
}

func closeConnOnCancel(ctx context.Context, conn net.Conn) func() {
	if ctx == nil || conn == nil {
		return func() {}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return func() { stop() }
}

func readUntil(conn deadlineReader, buf []byte, timeout time.Duration, stop func([]byte) bool) (int, error) {
	deadline := time.Now().Add(timeout)
	total := 0
	for total < len(buf) {
		if timeout > 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return total, nil
			}
			window := remaining
			if total > 0 {
				window = readWindow(remaining)
			}
			conn.SetReadDeadline(time.Now().Add(window))
		} else {
			conn.SetReadDeadline(time.Now().Add(readIdleTimeout))
		}

		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
			if stop != nil && stop(buf[:total]) {
				return total, nil
			}
		}
		if err != nil {
			if total > 0 {
				return total, nil
			}
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
	return total, nil
}

func readWindow(remaining time.Duration) time.Duration {
	if remaining < readIdleTimeout {
		return remaining
	}
	return readIdleTimeout
}

// fix regexp only use utf-8, ref: https://paper.seebug.org/1679/
func convert2utf8(src string) string {
	var dst string
	for i, r := range src {
		var v string
		if r == utf8.RuneError {
			// convert, rune => string, intstring() => encoderune()
			v = string(src[i])
		} else {
			v = string(r)
		}
		dst += v
	}
	return dst
}
