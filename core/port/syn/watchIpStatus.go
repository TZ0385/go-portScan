//go:build !nosyn

package syn

import (
	"context"
	"github.com/XinRoom/go-portScan/core/port"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	watchIpStatusSweepInterval = 250 * time.Millisecond
	synSourcePortMin           = uint16(49000)
	synSourcePortMax           = uint16(58999)
)

type probeKey struct {
	ip      string
	srcPort uint16
	dstPort uint16
}

type pendingProbe struct {
	key       probeKey
	option    port.IpOption
	startedAt time.Time
	sentAt    time.Time

	ctx     context.Context
	cancel  context.CancelFunc
	retried bool
	retry   func() error
}

func (p pendingProbe) context() context.Context {
	if p.ctx != nil {
		return p.ctx
	}
	return context.Background()
}

func (p pendingProbe) cancelContext() {
	if p.cancel != nil {
		p.cancel()
	}
}

// IP状态更新表
type watchIpStatusTable struct {
	probes      map[probeKey]pendingProbe
	nextSrcPort uint16
	lock        sync.RWMutex
	isDone      atomic.Bool
	// onProbeTimeout 返回 true 表示已由一次抽样重探接管，本轮不发送终态事件。
	onProbeTimeout func(pendingProbe) bool
}

func newWatchIpStatusTable(timeout time.Duration) (w *watchIpStatusTable) {
	w = &watchIpStatusTable{
		probes:      make(map[probeKey]pendingProbe),
		nextSrcPort: synSourcePortMin,
	}
	go w.cleanTimeout(timeout)
	return
}

func (w *watchIpStatusTable) RecordSentProbe(ip string, srcPort, dstPort uint16, sentAt time.Time, option port.IpOption) (probeKey, bool) {
	key := probeKey{ip: ip, srcPort: srcPort, dstPort: dstPort}
	w.lock.Lock()
	defer w.lock.Unlock()
	if _, exists := w.probes[key]; exists {
		return key, false
	}
	w.probes[key] = pendingProbe{key: key, option: option, startedAt: sentAt, sentAt: sentAt}
	return key, true
}

func (w *watchIpStatusTable) ReserveProbe(ip string, dstPort uint16, sentAt time.Time, option port.IpOption) (probeKey, pendingProbe, bool) {
	return w.ReserveProbeContext(context.Background(), nil, ip, dstPort, sentAt, option)
}

func (w *watchIpStatusTable) ReserveProbeContext(ctx context.Context, cancel context.CancelFunc, ip string, dstPort uint16, sentAt time.Time, option port.IpOption) (probeKey, pendingProbe, bool) {
	w.lock.Lock()
	defer w.lock.Unlock()

	startPort := w.nextSrcPort
	if startPort < synSourcePortMin || startPort > synSourcePortMax {
		startPort = synSourcePortMin
	}
	rangeSize := int(synSourcePortMax-synSourcePortMin) + 1
	startOffset := int(startPort - synSourcePortMin)

	for offset := 0; offset < rangeSize; offset++ {
		srcPort := synSourcePortMin + uint16((startOffset+offset)%rangeSize)
		key := probeKey{ip: ip, srcPort: srcPort, dstPort: dstPort}
		if _, exists := w.probes[key]; !exists {
			probe := pendingProbe{key: key, option: option, startedAt: sentAt, sentAt: sentAt, ctx: ctx, cancel: cancel}
			w.probes[key] = probe
			if srcPort == synSourcePortMax {
				w.nextSrcPort = synSourcePortMin
			} else {
				w.nextSrcPort = srcPort + 1
			}
			return key, probe, true
		}
	}

	return probeKey{}, pendingProbe{}, false
}

func (w *watchIpStatusTable) TakeProbe(ip string, srcPort, dstPort uint16) (pendingProbe, bool) {
	key := probeKey{ip: ip, srcPort: srcPort, dstPort: dstPort}
	w.lock.Lock()
	defer w.lock.Unlock()
	probe, ok := w.probes[key]
	if !ok {
		return pendingProbe{}, false
	}
	delete(w.probes, key)
	return probe, true
}

func (w *watchIpStatusTable) DropProbe(key probeKey) (pendingProbe, bool) {
	w.lock.Lock()
	defer w.lock.Unlock()
	probe, ok := w.probes[key]
	if ok {
		delete(w.probes, key)
	}
	return probe, ok
}

func (w *watchIpStatusTable) SetRetry(key probeKey, retry func() error) bool {
	w.lock.Lock()
	defer w.lock.Unlock()
	probe, ok := w.probes[key]
	if !ok {
		return false
	}
	probe.retry = retry
	w.probes[key] = probe
	return true
}

func (w *watchIpStatusTable) TouchProbe(key probeKey, sentAt time.Time) bool {
	w.lock.Lock()
	defer w.lock.Unlock()
	probe, ok := w.probes[key]
	if !ok {
		return false
	}
	probe.sentAt = sentAt
	w.probes[key] = probe
	return true
}

func (w *watchIpStatusTable) RearmProbe(probe pendingProbe) bool {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.isDone.Load() || probe.context().Err() != nil {
		return false
	}
	if _, exists := w.probes[probe.key]; exists {
		return false
	}
	probe.retried = true
	w.probes[probe.key] = probe
	return true
}

func (w *watchIpStatusTable) Len() int {
	w.lock.RLock()
	defer w.lock.RUnlock()
	return len(w.probes)
}

// IsEmpty 判断目前表是否为空
func (w *watchIpStatusTable) IsEmpty() (empty bool) {
	w.lock.RLock()
	empty = len(w.probes) == 0
	w.lock.RUnlock()
	return
}

func (w *watchIpStatusTable) Close() {
	w.isDone.Store(true)
	w.lock.Lock()
	var pending []pendingProbe
	for key, probe := range w.probes {
		pending = append(pending, probe)
		delete(w.probes, key)
	}
	w.lock.Unlock()
	for _, probe := range pending {
		probe.option.EmitProbeDone(port.ProbeEvent{
			IP:        net.ParseIP(probe.key.ip),
			Port:      probe.key.dstPort,
			Outcome:   port.ProbeAborted,
			StartedAt: probe.startedAt,
		})
		probe.cancelContext()
	}
}

// 清理过期数据
func (w *watchIpStatusTable) cleanTimeout(timeout time.Duration) {
	for {
		if w.isDone.Load() {
			break
		}
		time.Sleep(watchIpStatusSweepInterval)
		w.lock.Lock()
		var expired []pendingProbe
		now := time.Now()
		for key, probe := range w.probes {
			if probe.context().Err() != nil || (!probe.sentAt.IsZero() && now.Sub(probe.sentAt) > timeout) {
				expired = append(expired, probe)
				delete(w.probes, key)
			}
		}
		w.lock.Unlock()
		for _, probe := range expired {
			w.finishExpiredProbe(probe)
		}
	}
}

func (w *watchIpStatusTable) finishExpiredProbe(probe pendingProbe) {
	// probe 已移出表后仍可能与 Close 交错；发送终态前再次判断，保证关闭统一收口为 Aborted。
	outcome := port.ProbeNoResponse
	if w.isDone.Load() || probe.context().Err() != nil {
		outcome = port.ProbeAborted
	} else if w.onProbeTimeout != nil && w.onProbeTimeout(probe) {
		return
	}
	probe.option.EmitProbeDone(port.ProbeEvent{
		IP:        net.ParseIP(probe.key.ip),
		Port:      probe.key.dstPort,
		Outcome:   outcome,
		StartedAt: probe.startedAt,
	})
	probe.cancelContext()
}
