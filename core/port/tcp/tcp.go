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
	ctx         context.Context
	cancel      context.CancelFunc
	timeout     time.Duration
	isDone      atomic.Bool
	option      port.ScannerOption
	wg          sync.WaitGroup
	inflight    chan struct{}
	fingerPool  *port.WorkPool
	closeOnce   sync.Once
}

const (
	defaultMaxConcurrent     = 512
	defaultFingerConcurrency = 64
)

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
	maxConcurrent := option.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	fingerConcurrency := option.FingerConcurrency
	if fingerConcurrency <= 0 {
		fingerConcurrency = defaultFingerConcurrency
	}
	burst := option.Rate / 100
	if burst < 1 {
		burst = 1
	}
	ts = &TcpScanner{
		retChan:     retChan,
		limiter:     limiter.NewLimiter(limiter.Limit(option.Rate), burst),
		hostLimiter: newHostLimiter(option.RatePreHost),
		ctx:         ctx,
		cancel:      cancel,
		timeout:     time.Duration(option.Timeout) * time.Millisecond,
		option:      option,
		inflight:    make(chan struct{}, maxConcurrent),
		fingerPool:  port.NewWorkPool(fingerConcurrency, fingerConcurrency*4),
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
	return ts.scanContext(ts.ctx, nil, false, ip, dst, ipOption)
}

func (ts *TcpScanner) ProbeContext(ctx context.Context, ip net.IP, dst uint16, ipOption port.IpOption) error {
	ctx, cancel := linkedContext(ctx, ts.ctx)
	return ts.scanContext(ctx, cancel, true, ip, dst, ipOption)
}

func (ts *TcpScanner) scanContext(ctx context.Context, probeCancel context.CancelFunc, applyGlobalLimit bool, ip net.IP, dst uint16, ipOption port.IpOption) error {
	if ts.isDone.Load() {
		if probeCancel != nil {
			probeCancel()
		}
		return errors.New("scanner is closed")
	}
	if err := ctx.Err(); err != nil {
		if probeCancel != nil {
			probeCancel()
		}
		return err
	}
	select {
	// TCP 在途上限约束连接资源；它与指纹池分离，避免慢指纹占住拨号额度。
	case ts.inflight <- struct{}{}:
	case <-ctx.Done():
		if probeCancel != nil {
			probeCancel()
		}
		return ctx.Err()
	}
	releaseCapacity := func() { <-ts.inflight }
	if err := ts.waitHostLimiter(ctx, ip); err != nil {
		releaseCapacity()
		if probeCancel != nil {
			probeCancel()
		}
		return err
	}
	if applyGlobalLimit {
		// 全局 token 必须紧邻真实 Dial 获取，避免先取 token 后长时间排队造成补偿性突发。
		if err := ts.limiter.Wait(ctx); err != nil {
			releaseCapacity()
			if probeCancel != nil {
				probeCancel()
			}
			return err
		}
	}
	// 限速器可能在成功返回的同时触发取消，调度 Dial 前再做一次便宜检查。
	if err := ctx.Err(); err != nil {
		releaseCapacity()
		if probeCancel != nil {
			probeCancel()
		}
		return err
	}
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		defer releaseCapacity()
		handedOff := false
		defer func() {
			if !handedOff && probeCancel != nil {
				probeCancel()
			}
		}()
		startedAt := time.Now()
		openIpPort := port.OpenIpPort{
			Ip:       ip,
			Port:     dst,
			IpOption: ipOption,
		}
		conn, dialErr := (&net.Dialer{Timeout: ts.timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(dst))))
		if conn == nil {
			outcome := tcpProbeOutcome(ctx, dialErr)
			ipOption.EmitProbeDone(port.ProbeEvent{
				IP:        ip,
				Port:      dst,
				Outcome:   outcome,
				Err:       dialErr,
				StartedAt: startedAt,
			})
			return
		}
		_ = conn.Close()

		if !ipOption.FingerPrint && !ipOption.Httpx {
			_ = port.EmitOpenProbeResult(ctx, ts.retChan, openIpPort, startedAt)
			return
		}

		if ts.fingerPool.TrySubmit(func() {
			if probeCancel != nil {
				defer probeCancel()
			}
			ts.enrichAndEmit(ctx, openIpPort, startedAt)
		}) {
			handedOff = true
		} else {
			// 指纹属于可选增强。队列饱和时仍必须保留已确认的开放端口。
			openIpPort.Service = "unknown"
			_ = port.EmitOpenProbeResult(ctx, ts.retChan, openIpPort, startedAt)
		}
	}()
	return nil
}

func (ts *TcpScanner) enrichAndEmit(ctx context.Context, openIpPort port.OpenIpPort, startedAt time.Time) {
	var probeDialErr bool
	fingerTimeout := ts.option.FingerTimeoutDuration()
	resultCtx := ctx
	// 服务识别与可选 HTTP 探测共享同一个单端口墙钟预算，防止阶段时长叠加。
	ctx, cancel := context.WithTimeout(ctx, fingerTimeout)
	defer cancel()
	if openIpPort.FingerPrint {
		openIpPort.Service, openIpPort.Banner, probeDialErr = fingerprint.PortIdentifyContext(ctx, "tcp", openIpPort.Ip, openIpPort.Port, fingerTimeout)
		if probeDialErr || ctx.Err() != nil {
			_ = port.EmitOpenProbeResult(resultCtx, ts.retChan, openIpPort, startedAt)
			return
		}
	}
	if openIpPort.Httpx && (openIpPort.Service == "" || openIpPort.Service == "http" || openIpPort.Service == "https") {
		openIpPort.HttpInfo, openIpPort.Banner, probeDialErr = fingerprint.ProbeHttpInfoContext(ctx, openIpPort.Ip.String(), openIpPort.Port, openIpPort.Service, fingerTimeout)
		if probeDialErr || ctx.Err() != nil {
			_ = port.EmitOpenProbeResult(resultCtx, ts.retChan, openIpPort, startedAt)
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
	_ = port.EmitOpenProbeResult(resultCtx, ts.retChan, openIpPort, startedAt)
}

func (ts *TcpScanner) Wait() {
	ts.wg.Wait()
	ts.fingerPool.Wait()
}

func (ts *TcpScanner) Close() {
	ts.closeOnce.Do(func() {
		ts.isDone.Store(true)
		if ts.cancel != nil {
			ts.cancel()
		}
		ts.wg.Wait()
		ts.fingerPool.Close()
	})
}

func (ts *TcpScanner) WaitLimiter() error {
	return ts.limiter.Wait(ts.ctx)
}

func (ts *TcpScanner) waitHostLimiter(ctx context.Context, ip net.IP) error {
	if ts.hostLimiter == nil || ip == nil {
		return nil
	}
	return ts.hostLimiter.Wait(ctx, ip.String())
}

func newHostLimiter(ratePerHost int) hostLimiter {
	return port.NewHostLimiterStore(ratePerHost)
}

func linkedContext(parent, scanner context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(scanner, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}
