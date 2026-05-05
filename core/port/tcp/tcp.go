package tcp

import (
	"context"
	"errors"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	limiter "golang.org/x/time/rate"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var DefaultTcpOption = port.ScannerOption{
	Rate:          1000,
	Timeout:       800,
	FingerTimeout: 2000,
}

type hostLimiter interface {
	Wait(context.Context, string) error
}

type TcpScanner struct {
	ports       []uint16             // 指定端口
	retChan     chan port.OpenIpPort // 返回值队列
	limiter     *limiter.Limiter
	hostLimiter hostLimiter
	hostPacer   *port.HostPacerStore
	ctx         context.Context
	cancel      context.CancelFunc
	timeout     time.Duration
	isDone      atomic.Bool
	option      port.ScannerOption
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

// NewTcpScanner Tcp扫描器
func NewTcpScanner(retChan chan port.OpenIpPort, option port.ScannerOption) (ts *TcpScanner, err error) {
	// option verify
	if option.Rate < 10 {
		err = errors.New("rate can not set < 10")
		return
	}
	if option.Timeout <= 0 {
		err = errors.New("timeout can not set to 0")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	ts = &TcpScanner{
		retChan:     retChan,
		limiter:     limiter.NewLimiter(limiter.Every(time.Second/time.Duration(option.Rate)), option.Rate/10),
		hostLimiter: newHostLimiter(option.RatePreHost),
		hostPacer:   port.NewHostPacerStore(option.RatePreHost, time.Minute, time.Now),
		ctx:         ctx,
		cancel:      cancel,
		timeout:     time.Duration(option.Timeout) * time.Millisecond,
		option:      option,
	}
	if ts.hostPacer != nil {
		ts.hostPacer.SetDebug(option.Debug, nil)
	}

	return
}

// Scan 对指定IP和dis port进行扫描
func (ts *TcpScanner) Scan(ip net.IP, dst uint16, ipOption port.IpOption) error {
	if ts.isDone.Load() {
		return errors.New("scanner is closed")
	}
	if err := ts.waitHostLimiter(ip); err != nil {
		return err
	}
	if err := ts.waitHostPacer(ip); err != nil {
		return err
	}
	// wait 返回后仍可能已经被 Close/cancel，这里要在启动 goroutine 前再次拦截。
	if err := ts.ctx.Err(); err != nil {
		return err
	}
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		//fmt.Println(1)
		openIpPort := port.OpenIpPort{
			Ip:   ip,
			Port: dst,
			IpOption: port.IpOption{
				Ext: ipOption.Ext,
			},
		}
		start := time.Now()
		conn, _ := (&net.Dialer{Timeout: ts.timeout}).DialContext(ts.ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(dst))))
		if conn != nil {
			ts.observeHostSample(ip.String(), port.HostSample{RTT: time.Since(start), HasRTT: true})
			conn.Close()
		} else {
			return
		}
		if !ipOption.FingerPrint && !ipOption.Httpx {
			ts.emitResult(openIpPort)
			return
		}

		// The initial TCP connect above already confirmed the port is open.
		// Later probe dial/timeouts only mean enrichment failed, not that the port disappeared.
		var probeDialErr bool
		fingerTimeout := ts.option.FingerTimeoutDuration()
		if ipOption.FingerPrint {
			openIpPort.Service, openIpPort.Banner, probeDialErr = fingerprint.PortIdentify("tcp", ip, dst, fingerTimeout)
			if probeDialErr {
				ts.emitResult(openIpPort)
				return
			}
		}
		if ipOption.Httpx && (openIpPort.Service == "" || openIpPort.Service == "http" || openIpPort.Service == "https") {
			openIpPort.HttpInfo, openIpPort.Banner, probeDialErr = fingerprint.ProbeHttpInfo(ip.String(), dst, openIpPort.Service, fingerTimeout)
			if probeDialErr {
				ts.emitResult(openIpPort)
				return
			}
			if openIpPort.HttpInfo != nil {
				if strings.HasPrefix(openIpPort.HttpInfo.Url, "https") {
					openIpPort.Service = "https"
				} else {
					openIpPort.Service = "http"
				}
			}
		}
		ts.emitResult(openIpPort)
	}()
	return nil
}

func (ts *TcpScanner) Wait() {
	ts.wg.Wait()
}

// Close scanner resources. The caller owns retChan lifecycle.
func (ts *TcpScanner) Close() {
	ts.closeOnce.Do(func() {
		ts.isDone.Store(true)
		if ts.cancel != nil {
			ts.cancel()
		}
		// Wait for in-flight scans to stop touching retChan before returning.
		ts.wg.Wait()
	})
}

// WaitLimiter Waiting for the speed limit
func (ts *TcpScanner) WaitLimiter() error {
	return ts.limiter.Wait(ts.ctx)
}

func (ts *TcpScanner) waitHostLimiter(ip net.IP) error {
	if ts.hostLimiter == nil || ip == nil {
		return nil
	}
	return ts.hostLimiter.Wait(ts.ctx, ip.String())
}

func (ts *TcpScanner) waitHostPacer(ip net.IP) error {
	if ts.hostPacer == nil || ip == nil {
		return nil
	}
	return ts.hostPacer.Wait(ts.ctx, ip.String())
}

func (ts *TcpScanner) observeHostSample(host string, sample port.HostSample) {
	if ts.hostPacer == nil {
		return
	}
	ts.hostPacer.Observe(host, sample)
}

func (ts *TcpScanner) emitResult(openIpPort port.OpenIpPort) bool {
	select {
	case <-ts.ctx.Done():
		return false
	// Result delivery shares the same cancellation path so Close does not race with channel sends.
	case ts.retChan <- openIpPort:
		return true
	}
}

func newHostLimiter(ratePerHost int) hostLimiter {
	return port.NewHostLimiterStore(ratePerHost)
}
