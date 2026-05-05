//go:build !nosyn

package syn

import (
	"github.com/XinRoom/go-portScan/core/port"
	"sync"
	"sync/atomic"
	"time"
)

type watchIpStatus struct {
	ReceivedPort map[uint16]struct{}
	SentPortAt   map[uint16]time.Time
	LastTime     time.Time
	IpOption     port.IpOption
}

// IP状态更新表
type watchIpStatusTable struct {
	watchIpS map[string]*watchIpStatus
	lock     sync.RWMutex
	isDone   atomic.Bool
	// onHostTimeout 仅表示 host 观察窗口结束，不参与 pacing 决策。
	onHostTimeout func(string)
}

func newWatchIpStatusTable(timeout time.Duration) (w *watchIpStatusTable) {
	w = &watchIpStatusTable{
		watchIpS: make(map[string]*watchIpStatus),
	}
	go w.cleanTimeout(timeout)
	return
}

// CreateOrUpdateLastTime 新建或者更新LastTime
func (w *watchIpStatusTable) CreateOrUpdateLastTime(ip string, ipOption port.IpOption) {
	lastTime := time.Now()
	w.lock.Lock()
	wi, ok := w.watchIpS[ip]
	if ok {
		wi.LastTime = lastTime
	} else {
		w.watchIpS[ip] = &watchIpStatus{LastTime: lastTime, ReceivedPort: make(map[uint16]struct{}), SentPortAt: make(map[uint16]time.Time), IpOption: ipOption}
	}
	w.lock.Unlock()
}

// RecordSentPort 记录某个端口的发送时间，用于计算 RTT。
func (w *watchIpStatusTable) RecordSentPort(ip string, port uint16, sentAt time.Time) {
	w.lock.Lock()
	wi, ok := w.watchIpS[ip]
	if ok {
		wi.SentPortAt[port] = sentAt
		wi.LastTime = sentAt
	}
	w.lock.Unlock()
}

// RecordPort 记录收到的端口
func (w *watchIpStatusTable) RecordPort(ip string, port uint16) {
	w.lock.Lock()
	wi, ok := w.watchIpS[ip]
	if ok {
		wi.ReceivedPort[port] = struct{}{}
	}
	w.lock.Unlock()
}

// HasPort 判断是否检测过对应端口
func (w *watchIpStatusTable) HasPort(ip string, port uint16) (has bool) {
	w.lock.RLock()
	wi, ok := w.watchIpS[ip]
	if ok {
		_, has = wi.ReceivedPort[port]
	}
	w.lock.RUnlock()
	return
}

// TakeSentPortTime 取出端口发送时间，命中后删除，避免重复记 RTT。
func (w *watchIpStatusTable) TakeSentPortTime(ip string, port uint16) (sentAt time.Time, ok bool) {
	w.lock.Lock()
	wi, has := w.watchIpS[ip]
	if has {
		sentAt, ok = wi.SentPortAt[port]
		if ok {
			delete(wi.SentPortAt, port)
		}
	}
	w.lock.Unlock()
	return
}

// GetIpOption 判断是否在监视对应IP
func (w *watchIpStatusTable) GetIpOption(ip string) (ipOption port.IpOption, has bool) {
	w.lock.RLock()
	wi, has := w.watchIpS[ip]
	if has {
		ipOption = wi.IpOption
	}
	w.lock.RUnlock()
	return
}

// IsEmpty 判断目前表是否为空
func (w *watchIpStatusTable) IsEmpty() (empty bool) {
	w.lock.RLock()
	empty = len(w.watchIpS) == 0
	w.lock.RUnlock()
	return
}

func (w *watchIpStatusTable) Close() {
	w.isDone.Store(true)
	w.lock.Lock()
	w.watchIpS = make(map[string]*watchIpStatus)
	w.lock.Unlock()
}

// 清理过期数据
func (w *watchIpStatusTable) cleanTimeout(timeout time.Duration) {
	var needDel map[string]struct{}
	for {
		needDel = make(map[string]struct{})
		if w.isDone.Load() {
			break
		}
		time.Sleep(time.Second)
		w.lock.RLock()
		for k, v := range w.watchIpS {
			if time.Since(v.LastTime) > timeout {
				needDel[k] = struct{}{}
			}
		}
		w.lock.RUnlock()
		if len(needDel) > 0 {
			for k := range needDel {
				if w.onHostTimeout != nil {
					w.onHostTimeout(k)
				}
				w.lock.Lock()
				delete(w.watchIpS, k)
				w.lock.Unlock()
			}
		}
	}
}
