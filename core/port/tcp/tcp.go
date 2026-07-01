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
	ports       []uint16
	retChan     chan port.OpenIpPort
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

func NewTcpScanner(retChan chan port.OpenIpPort, option port.ScannerOption) (ts *TcpScanner, err error) {
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

func tcpProbeOutcome(ctx context.Context, err error) port.ProbeOutcome {
	if ctx.Err() != nil {
		return port.ProbeAborted
	}
	if err == nil {
		return port.ProbeOpen
	}
	errText := strings.ToLower(err.Error())
	if strings.Contains(errText, "refused") || strings.Contains(errText, "actively refused") {
		return port.ProbeClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return port.ProbeNoResponse
	}
	if strings.Contains(errText, "timeout") {
		return port.ProbeNoResponse
	}
	return port.ProbeError
}

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
	if err := ts.ctx.Err(); err != nil {
		return err
	}
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		startedAt := time.Now()
		openIpPort := port.OpenIpPort{
			Ip:       ip,
			Port:     dst,
			IpOption: ipOption,
		}
		conn, dialErr := (&net.Dialer{Timeout: ts.timeout}).DialContext(ts.ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(dst))))
		if conn == nil {
			outcome := tcpProbeOutcome(ts.ctx, dialErr)
			ipOption.EmitProbeDone(port.ProbeEvent{
				IP:        ip,
				Port:      dst,
				Outcome:   outcome,
				Err:       dialErr,
				StartedAt: startedAt,
			})
			return
		}
		ts.observeHostSample(ip.String(), port.HostSample{RTT: time.Since(startedAt), HasRTT: true})
		conn.Close()

		if !ipOption.FingerPrint && !ipOption.Httpx {
			_ = port.EmitOpenProbeResult(ts.ctx, ts.retChan, openIpPort, startedAt)
			return
		}

		var probeDialErr bool
		fingerTimeout := ts.option.FingerTimeoutDuration()
		if ipOption.FingerPrint {
			openIpPort.Service, openIpPort.Banner, probeDialErr = fingerprint.PortIdentify("tcp", ip, dst, fingerTimeout)
			if probeDialErr {
				_ = port.EmitOpenProbeResult(ts.ctx, ts.retChan, openIpPort, startedAt)
				return
			}
		}
		if ipOption.Httpx && (openIpPort.Service == "" || openIpPort.Service == "http" || openIpPort.Service == "https") {
			openIpPort.HttpInfo, openIpPort.Banner, probeDialErr = fingerprint.ProbeHttpInfo(ip.String(), dst, openIpPort.Service, fingerTimeout)
			if probeDialErr {
				_ = port.EmitOpenProbeResult(ts.ctx, ts.retChan, openIpPort, startedAt)
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
		_ = port.EmitOpenProbeResult(ts.ctx, ts.retChan, openIpPort, startedAt)
	}()
	return nil
}

func (ts *TcpScanner) Wait() {
	ts.wg.Wait()
}

func (ts *TcpScanner) Close() {
	ts.closeOnce.Do(func() {
		ts.isDone.Store(true)
		if ts.cancel != nil {
			ts.cancel()
		}
		ts.wg.Wait()
	})
}

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

func newHostLimiter(ratePerHost int) hostLimiter {
	return port.NewHostLimiterStore(ratePerHost)
}
