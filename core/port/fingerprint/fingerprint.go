package fingerprint

import (
	"bytes"
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
		return make([]byte, 4096)
	},
}

func identifyBudget(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 2 * time.Second
	}
	// Fingerprint matching may need several protocol attempts; cap the total wall time instead of
	// reusing the full timeout on every rule.
	budget := timeout * 4
	if budget < 2*time.Second {
		return 2 * time.Second
	}
	if budget > 8*time.Second {
		return 8 * time.Second
	}
	return budget
}

func remainingTimeout(deadline time.Time, timeout time.Duration) (time.Duration, bool) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, false
	}
	if timeout <= 0 || remaining < timeout {
		return remaining, true
	}
	return timeout, true
}

// PortIdentify 端口识别
func PortIdentify(network string, ip net.IP, _port uint16, dailTimeout time.Duration) (serviceName string, banner []byte, isDialErr bool) {
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
			sn2, banner2, isDialErr2 := matchRule(network, ip, _port, "https", attemptTimeout)
			if !isDialErr && sn2 != "" {
				sn = sn2
				banner = banner2
				isDialErr = isDialErr2
			}
		}
	}()

	// 优先判断port可能的服务
	if serviceNames, ok := portServiceOrder[_port]; ok {
		for _, service := range serviceNames {
			attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
			if !ok {
				return unknown, banner, false
			}
			recordMatched(service)
			sn, banner, isDialErr = matchRule(network, ip, _port, service, attemptTimeout)
			if sn != "" {
				return sn, banner, false
			} else if isDialErr {
				return unknown, banner, isDialErr
			}
		}
	}

	var lastDailTime time.Duration

	// onlyRecv
	{
		var conn net.Conn
		var n int
		buf := readBufPool.Get().([]byte)
		defer func() {
			readBufPool.Put(buf)
		}()
		address := net.JoinHostPort(ip.String(), strconv.Itoa(int(_port)))
		now := time.Now()
		attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
		if !ok {
			return unknown, banner, false
		}
		conn, _ = net.DialTimeout(network, address, attemptTimeout)
		if conn == nil {
			return unknown, banner, true
		}
		lastDailTime = time.Since(now) * 2
		if lastDailTime < dailTimeout || dailTimeout <= 0 {
			dailTimeout = lastDailTime
			if dailTimeout < 250*time.Millisecond {
				dailTimeout = 250 * time.Millisecond
			}
		}
		attemptTimeout, ok = remainingTimeout(deadline, dailTimeout)
		if !ok {
			conn.Close()
			return unknown, banner, false
		}
		n, _ = read(conn, buf, attemptTimeout)
		conn.Close()
		if n != 0 {
			banner = make([]byte, n)
			copy(banner, buf[:n])
			for _, service := range onlyRecv {
				_, ok := matchedRule[service]
				if ok {
					continue
				}
				for _, rule := range serviceRules[service].DataGroup {
					if matchRuleWhithBuf(buf[:n], ip, _port, rule) {
						return service, banner, false
					}
				}

			}
		}
		for _, service := range onlyRecv {
			recordMatched(service)
		}
	}

	// 优先判断Top服务
	for _, service := range serviceOrder {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
		if !ok {
			return unknown, banner, false
		}
		recordMatched(service)
		sn, banner, isDialErr = matchRule(network, ip, _port, service, attemptTimeout)
		if sn != "" {
			return sn, banner, false
		} else if isDialErr {
			return unknown, banner, true
		}
	}

	// other
	for _, service := range serviceRuleOrder {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		attemptTimeout, ok := remainingTimeout(deadline, dailTimeout)
		if !ok {
			return unknown, banner, false
		}
		sn, banner, isDialErr = matchRule(network, ip, _port, service, attemptTimeout)
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
func matchRule(network string, ip net.IP, _port uint16, serviceName string, dailTimeout time.Duration) (serviceNameRet string, banner []byte, isDialErr bool) {
	var err error
	var isTls bool
	var conn net.Conn
	var connTls *tls.Conn

	address := net.JoinHostPort(ip.String(), strconv.Itoa(int(_port)))

	serviceRule2 := serviceRules[serviceName]
	flowsService := groupFlows[serviceName]

	// 建立连接
	if serviceRule2.Tls {
		// tls
		connTls, err = tls.DialWithDialer(&net.Dialer{Timeout: dailTimeout}, network, address, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
		if err != nil {
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
		isTls = true
	} else {
		conn, err = net.DialTimeout(network, address, dailTimeout)
		if conn == nil {
			isDialErr = true
			return
		}
		defer conn.Close()
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
			if isTls {
				n, err = read(connTls, buf, dailTimeout)
			} else {
				n, err = read(conn, buf, dailTimeout)
			}
			// 出错就退出
			if n == 0 {
				return
			}
			banner = make([]byte, n)
			copy(banner, buf[:n])
			// 包含数据就正确
			if matchRuleWhithBuf(buf[:n], ip, _port, rule) {
				serviceNameRet = serviceName
				return
			}
			// 可归并的服务规则组
			for _, s := range flowsService {
				for _, rule2 := range serviceRules[s].DataGroup {
					if rule2.Action == ActionSend {
						continue
					}
					if matchRuleWhithBuf(buf[:n], ip, _port, rule2) {
						serviceNameRet = s
						return
					}
				}
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

func read(conn interface{}, buf []byte, timeout time.Duration) (int, error) {
	switch conn.(type) {
	case net.Conn:
		conn.(net.Conn).SetReadDeadline(time.Now().Add(timeout))
		return conn.(net.Conn).Read(buf[:])
	case *tls.Conn:
		conn.(*tls.Conn).SetReadDeadline(time.Now().Add(timeout))
		return conn.(*tls.Conn).Read(buf[:])
	}
	return 0, errors.New("unknown type")
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
