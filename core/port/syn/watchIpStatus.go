//go:build !nosyn

package syn

import (
	"github.com/XinRoom/go-portScan/core/port"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	watchIpStatusSweepInterval = time.Second
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
}

// IP状态更新表
type watchIpStatusTable struct {
	probes      map[probeKey]pendingProbe
	nextSrcPort uint16
	lock        sync.RWMutex
	isDone      atomic.Bool
	// onHostTimeout 仅表示 host 观察窗口结束，不参与 pacing 决策。
	onHostTimeout func(string)
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
			probe := pendingProbe{key: key, option: option, startedAt: sentAt, sentAt: sentAt}
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
		expiredHosts := make(map[string]struct{})
		now := time.Now()
		for key, probe := range w.probes {
			if now.Sub(probe.sentAt) > timeout {
				expired = append(expired, probe)
				expiredHosts[key.ip] = struct{}{}
				delete(w.probes, key)
			}
		}
		w.lock.Unlock()
		for ip := range expiredHosts {
			if w.onHostTimeout != nil {
				w.onHostTimeout(ip)
			}
		}
		for _, probe := range expired {
			probe.option.EmitProbeDone(port.ProbeEvent{
				IP:        net.ParseIP(probe.key.ip),
				Port:      probe.key.dstPort,
				Outcome:   port.ProbeNoResponse,
				StartedAt: probe.startedAt,
			})
		}
	}
}
