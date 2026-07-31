//go:build !nosyn

package syn

import (
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	limiter "golang.org/x/time/rate"
)

const (
	adaptiveEvaluateInterval = 2 * time.Second
	adaptiveHealthyWindows   = 3
	adaptiveMinRetrySamples  = 5
)

// synAdaptiveLimiter 只根据本机明确拥塞和少量重探恢复情况调速，
// 普通无响应不参与决策，避免把防火墙过滤误判为网络拥塞。
type synAdaptiveLimiter struct {
	mu             sync.Mutex
	enabled        bool
	minRate        int
	maxRate        int
	currentRate    int
	lastEvaluate   time.Time
	lastPcapDrop   int
	healthyWindows int
	probes         uint64
	retrySuccess   int
	retryFailure   int
	writeErrors    int
}

func newSynAdaptiveLimiter(maxRate, minRate int, now time.Time) *synAdaptiveLimiter {
	c := &synAdaptiveLimiter{maxRate: maxRate, currentRate: maxRate, lastEvaluate: now}
	if minRate > 0 && minRate < maxRate {
		c.enabled = true
		c.minRate = minRate
	}
	return c
}

func (c *synAdaptiveLimiter) shouldSampleProbe() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return false
	}
	c.probes++
	return c.probes%100 == 0
}

func (c *synAdaptiveLimiter) recordRetry(success bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if success {
		c.retrySuccess++
	} else {
		c.retryFailure++
	}
	c.mu.Unlock()
}

func (c *synAdaptiveLimiter) recordWriteError() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.writeErrors++
	c.mu.Unlock()
}

// beginEvaluation 在读取 pcap 统计前占领本轮窗口，避免每个探针都进入系统统计路径。
func (c *synAdaptiveLimiter) beginEvaluation(now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || now.Sub(c.lastEvaluate) < adaptiveEvaluateInterval {
		return false
	}
	c.lastEvaluate = now
	return true
}

func (c *synAdaptiveLimiter) evaluateClaimed(pending, pendingCapacity int, stats *pcap.Stats) (int, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pcapDrop := 0
	if stats != nil {
		total := stats.PacketsDropped + stats.PacketsIfDropped
		if total > c.lastPcapDrop {
			pcapDrop = total - c.lastPcapDrop
		}
		c.lastPcapDrop = total
	}
	retrySamples := c.retrySuccess + c.retryFailure
	retryRecoveryHigh := retrySamples >= adaptiveMinRetrySamples && c.retrySuccess*100 >= retrySamples*30
	pendingHigh := pendingCapacity > 0 && pending*100 >= pendingCapacity*70

	oldRate := c.currentRate
	reason := ""
	switch {
	case pcapDrop > 0 || c.writeErrors > 0 || pendingHigh:
		c.currentRate = maxInt(c.minRate, c.currentRate*70/100)
		c.healthyWindows = 0
		reason = "local_congestion"
	case retryRecoveryHigh:
		c.currentRate = maxInt(c.minRate, c.currentRate*80/100)
		c.healthyWindows = 0
		reason = "retry_recovered"
	default:
		c.healthyWindows++
		if c.healthyWindows >= adaptiveHealthyWindows && c.currentRate < c.maxRate {
			step := maxInt(10, c.maxRate*5/100)
			c.currentRate = minInt(c.maxRate, c.currentRate+step)
			c.healthyWindows = 0
			reason = "healthy_recovery"
		}
	}
	c.retrySuccess = 0
	c.retryFailure = 0
	c.writeErrors = 0
	return c.currentRate, reason, c.currentRate != oldRate
}

func applyAdaptiveRate(l *limiter.Limiter, now time.Time, newRate int) {
	if l == nil || newRate <= 0 {
		return
	}
	burst := maxInt(1, newRate/100)
	l.SetLimitAt(now, limiter.Limit(newRate))
	l.SetBurstAt(now, burst)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
