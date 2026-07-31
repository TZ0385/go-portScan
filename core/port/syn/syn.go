//go:build !nosyn

package syn

import (
	"context"
	"errors"
	"fmt"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	limiter "golang.org/x/time/rate"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type hostLimiter interface {
	Wait(context.Context, string) error
}

type synOpenProbe struct {
	result port.OpenIpPort
	probe  pendingProbe
}

type SynScanner struct {
	srcMac, gwMac net.HardwareAddr // macAddr
	devName       string           // eth dev(pcap)

	// gateway (if applicable), and source IP addresses to use.
	srcIp, srcIp6 net.IP

	// pcap
	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send() method.
	opts gopacket.SerializeOptions

	// Buffer复用
	bufPool *sync.Pool
	// sendPacket 仅用于测试中注入发送失败，生产默认走 send。
	sendPacket func(...gopacket.SerializableLayer) error
	// 多个 host 任务可以并行准备 probe，但同一个 pcap handle 的写入与关闭必须串行。
	sendMu sync.Mutex

	//
	option         port.ScannerOption
	openPortChan   chan synOpenProbe // inside chan
	portProbeWg    sync.WaitGroup
	fingerPool     *port.WorkPool
	retChan        chan port.OpenIpPort // results chan
	limiter        *limiter.Limiter
	hostLimiter    hostLimiter
	ctx            context.Context
	cancel         context.CancelFunc
	watchIpStatusT *watchIpStatusTable // IpStatusCacheTable
	watchMacCacheT *watchMacCacheTable // MacCaches
	isDone         atomic.Bool
	closeOnce      sync.Once
	recvWg         sync.WaitGroup
	probeLoopWg    sync.WaitGroup
	adaptive       *synAdaptiveLimiter
	retryChan      chan pendingProbe
	retryWg        sync.WaitGroup
	pcapStats      func() (*pcap.Stats, error)
}

// NewSynScanner firstIp: Used to select routes; openPortChan: Result return channel
func NewSynScanner(firstIp net.IP, retChan chan port.OpenIpPort, option port.ScannerOption) (ss *SynScanner, err error) {
	// option verify
	if option.Rate < 10 {
		err = errors.New("rate can not set < 10")
		return
	}
	if option.Timeout <= 0 {
		// 超时表按固定周期清理，非正 timeout 会退化为异常短的响应窗口，必须在构造阶段拒绝。
		err = errors.New("timeout can not set to 0")
		return
	}

	var devName string
	var srcIp, srcIp6 net.IP
	var srcMac net.HardwareAddr
	var gw net.IP

	// specify dev
	if option.NextHop != "" {
		gw = net.ParseIP(option.NextHop)
		srcIp, srcIp6, srcMac, devName, err = GetMacByGw(gw)
	} else {
		// get router info
		srcIp, srcIp6, srcMac, gw, devName, err = GetRouter(firstIp)
	}
	if err != nil {
		return
	}

	if devName == "" {
		err = errors.New("get router info fail: no dev name")
		return
	}

	rand.Seed(time.Now().Unix())

	ctx, cancel := context.WithCancel(context.Background())
	fingerConcurrency := option.FingerConcurrency
	if fingerConcurrency <= 0 {
		fingerConcurrency = 64
	}
	burst := option.Rate / 100
	if burst < 1 {
		burst = 1
	}
	ss = &SynScanner{
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		srcIp:   srcIp,
		srcIp6:  srcIp6,
		srcMac:  srcMac,
		devName: devName,
		bufPool: &sync.Pool{
			New: func() interface{} {
				return gopacket.NewSerializeBuffer()
			},
		},
		option:         option,
		openPortChan:   make(chan synOpenProbe, cap(retChan)),
		fingerPool:     port.NewWorkPool(fingerConcurrency, fingerConcurrency*4),
		retChan:        retChan,
		limiter:        limiter.NewLimiter(limiter.Limit(option.Rate), burst),
		hostLimiter:    newHostLimiter(option.RatePreHost),
		ctx:            ctx,
		cancel:         cancel,
		watchIpStatusT: newWatchIpStatusTable(time.Duration(option.Timeout) * time.Millisecond),
		watchMacCacheT: newWatchMacCacheTable(),
		adaptive:       newSynAdaptiveLimiter(option.Rate, option.MiniRate, time.Now()),
		retryChan:      make(chan pendingProbe, 64),
	}
	ss.sendPacket = ss.send

	// Pcap
	// 每个包最大读取长度1024, 不开启混杂模式, no TimeOut
	handle, err := pcap.OpenLive(devName, 1024, false, pcap.BlockForever)
	if err != nil {
		ss.Close()
		ss = nil
		return
	}
	// Set filter, Reduce the number of monitoring packets
	if err = configureSynRecvFilter(handle, srcMac); err != nil {
		ss.Close()
		ss = nil
		return
	}
	ss.handle = handle
	ss.pcapStats = handle.Stats
	ss.watchIpStatusT.onProbeTimeout = ss.handleProbeTimeout
	ss.retryWg.Add(1)
	go func() {
		defer ss.retryWg.Done()
		ss.retryLoop()
	}()

	// start listen recv
	ss.recvWg.Add(1)
	go func() {
		defer ss.recvWg.Done()
		ss.recv()
	}()

	if gw != nil {
		// get gateway mac addr
		var dstMac net.HardwareAddr
		dstMac, err = ss.getHwAddr(gw)
		if err != nil {
			ss.Close()
			ss = nil
			return
		}
		ss.gwMac = dstMac
	}

	ss.probeLoopWg.Add(1)
	go func() {
		defer ss.probeLoopWg.Done()
		ss.portProbeHandle()
	}()

	return
}

func synRecvBPFFilter(mac net.HardwareAddr) string {
	// NDP 邻居通告没有扩展头，ICMPv6 Type 位于固定的 IPv6 负载起始偏移 40。
	return fmt.Sprintf(
		"ether dst %s && (arp || (ip and tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack) || tcp[tcpflags] & tcp-rst != 0)) || (ip6 and ip6[6] = 6 and (ip6[53] & 0x12 = 0x12 || ip6[53] & 0x04 != 0)) || (ip6 and ip6[6] = 58 and ip6[40] = 136))",
		mac.String(),
	)
}

type synBPFFilterHandle interface {
	SetBPFFilter(string) error
	Close()
}

func configureSynRecvFilter(handle synBPFFilterHandle, mac net.HardwareAddr) error {
	if err := handle.SetBPFFilter(synRecvBPFFilter(mac)); err != nil {
		handle.Close()
		return err
	}
	return nil
}

// Scan scans the dst IP address and port of this scanner.
func (ss *SynScanner) Scan(dstIp net.IP, dst uint16, ipOption port.IpOption) (err error) {
	return ss.scanContext(ss.ctx, nil, false, dstIp, dst, ipOption)
}

func (ss *SynScanner) ProbeContext(ctx context.Context, dstIp net.IP, dst uint16, ipOption port.IpOption) error {
	ctx, cancel := linkedContext(ctx, ss.ctx)
	return ss.scanContext(ctx, cancel, true, dstIp, dst, ipOption)
}

func (ss *SynScanner) scanContext(ctx context.Context, probeCancel context.CancelFunc, applyGlobalLimit bool, dstIp net.IP, dst uint16, ipOption port.IpOption) (err error) {
	cancelOnError := func() {
		if err != nil && probeCancel != nil {
			probeCancel()
		}
	}
	defer cancelOnError()
	// 原始 SYN 构包会按 IPv4/IPv6 访问地址字节，必须先拒绝不完整地址，避免库调用触发 panic。
	if dstIp == nil || dstIp.To16() == nil {
		return errors.New("invalid destination IP")
	}
	if dst == 0 {
		return errors.New("destination port must be greater than 0")
	}
	if ss.isDone.Load() {
		return io.EOF
	}
	if err = ss.waitHostLimiterContext(ctx, dstIp); err != nil {
		return err
	}
	// wait 返回后仍可能已经被 Close/cancel，这里要在后续状态变更前再次拦截。
	if err = ctx.Err(); err != nil {
		return err
	}

	ipStr := dstIp.String()

	// First off, get the MAC address we should be sending packets to.
	var dstMac net.HardwareAddr
	if ss.gwMac != nil {
		dstMac = ss.gwMac
	} else {
		// 内网IP
		mac := ss.watchMacCacheT.GetMac(ipStr)
		if mac != nil {
			dstMac = mac
		} else {
			dstMac, err = ss.getHwAddr(dstIp)
			if err != nil {
				return
			}
		}
	}

	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	var ip4 *layers.IPv4
	var ip6 *layers.IPv6
	if dstIp.To4() != nil {
		ip4 = &layers.IPv4{
			SrcIP:    ss.srcIp,
			DstIP:    dstIp,
			Version:  4,
			TTL:      128,
			Id:       uint16(40000 + rand.Intn(10000)),
			Flags:    layers.IPv4DontFragment,
			Protocol: layers.IPProtocolTCP,
		}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 = &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolTCP,
			HopLimit:   64,
			SrcIP:      ss.srcIp6,
			DstIP:      dstIp,
		}
	}
	if applyGlobalLimit {
		// 选路和邻居解析可能阻塞，全局 token 放到真正发包前获取，保证配置速率可预测。
		if err = ss.waitGlobalLimiter(ctx); err != nil {
			return err
		}
	}

	startedAt := time.Now()
	key, _, ok := ss.watchIpStatusT.ReserveProbeContext(ctx, probeCancel, ipStr, dst, startedAt, ipOption)
	if !ok {
		if probeCancel != nil {
			probeCancel()
		}
		return errors.New("syn source port range exhausted for pending probes")
	}
	srcPort := key.srcPort

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dst),
		SYN:     true,
		Window:  65280,
		Seq:     uint32(500000 + rand.Intn(10000)),
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0x50}, // 1360
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x08},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}
	// 发送时固定抽样 1%，只有样本 probe 保存重发闭包，避免所有 pending 都携带重探状态。
	sampleRetry := ss.adaptive != nil && ss.adaptive.shouldSampleProbe()
	var retry func() error
	// Send one packet per loop iteration until we've sent packets
	if ip4 != nil {
		tcp.SetNetworkLayerForChecksum(ip4)
		if sampleRetry {
			retry = func() error { return ss.sendPacket(&eth, ip4, &tcp) }
		}
		err = ss.sendPacket(&eth, ip4, &tcp)
	} else if ip6 != nil {
		tcp.SetNetworkLayerForChecksum(ip6)
		if sampleRetry {
			retry = func() error { return ss.sendPacket(&eth, ip6, &tcp) }
		}
		err = ss.sendPacket(&eth, ip6, &tcp)
	}
	if retry != nil {
		ss.watchIpStatusT.SetRetry(key, retry)
	}
	if err != nil {
		if ss.adaptive != nil {
			ss.adaptive.recordWriteError()
		}
		if probe, dropped := ss.watchIpStatusT.DropProbe(key); dropped {
			probe.option.EmitProbeDone(port.ProbeEvent{
				IP:        dstIp,
				Port:      dst,
				Outcome:   port.ProbeError,
				Err:       err,
				StartedAt: probe.startedAt,
			})
			probe.cancelContext()
		}
		return err
	}
	return
}

func (ss *SynScanner) Wait() {
	if ss.watchIpStatusT != nil {
		deadline := time.Now().Add(ss.pendingProbeWaitDuration())
		for {
			if ss.watchIpStatusT.IsEmpty() {
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond * 100)
		}
	}
	// wait inside chan is empty
	for len(ss.openPortChan) != 0 {
		time.Sleep(time.Millisecond * 20)
	}
	// wait portProbe task
	ss.portProbeWg.Wait()
	ss.fingerPool.Wait()
}

func (ss *SynScanner) pendingProbeWaitDuration() time.Duration {
	timeout := time.Duration(ss.option.Timeout) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(DefaultSynOption.Timeout) * time.Millisecond
	}
	if ss.adaptive != nil && ss.adaptive.enabled {
		return 2*timeout + 2*watchIpStatusSweepInterval + 100*time.Millisecond
	}
	return timeout + watchIpStatusSweepInterval + 100*time.Millisecond
}

// Close cleans up scanner-owned resources. The caller owns retChan lifecycle.
func (ss *SynScanner) Close() {
	ss.closeOnce.Do(func() {
		ss.isDone.Store(true)
		if ss.cancel != nil {
			ss.cancel()
		}
		ss.retryWg.Wait()
		if ss.handle != nil {
			// In linux, pcap can not stop when no packets to sniff with BlockForever
			// ref:https://github.com/google/gopacket/issues/890
			// ref:https://github.com/google/gopacket/issues/1089
			eth := layers.Ethernet{
				SrcMAC:       ss.srcMac,
				DstMAC:       ss.srcMac,
				EthernetType: layers.EthernetTypeARP,
			}
			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPReply,
				SourceHwAddress:   []byte(ss.srcMac),
				SourceProtAddress: []byte(ss.srcIp),
				DstHwAddress:      []byte(ss.srcMac),
				DstProtAddress:    []byte(ss.srcIp),
			}
			handle, _ := pcap.OpenLive(ss.devName, 1024, false, time.Second)
			buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
			_ = gopacket.SerializeLayers(buf, ss.opts, &eth, &arp)
			if handle != nil {
				_ = handle.WritePacketData(buf.Bytes())
				handle.Close()
			}
			buf.Clear()
			ss.bufPool.Put(buf)
			ss.sendMu.Lock()
			ss.handle.Close()
			ss.sendMu.Unlock()
		}
		if ss.watchMacCacheT != nil {
			ss.watchMacCacheT.Close()
		}
		if ss.watchIpStatusT != nil {
			ss.watchIpStatusT.Close()
		}
		// recv must stop first, otherwise it can still enqueue open ports while we are shutting down.
		ss.recvWg.Wait()
		close(ss.openPortChan)
		// portProbeHandle drains openPortChan and owns all probe workers.
		ss.probeLoopWg.Wait()
		ss.portProbeWg.Wait()
		ss.fingerPool.Close()
	})
}

// WaitLimiter Waiting for the speed limit
func (ss *SynScanner) WaitLimiter() error {
	return ss.waitGlobalLimiter(ss.ctx)
}

func (ss *SynScanner) waitGlobalLimiter(ctx context.Context) error {
	if ss.limiter == nil {
		return nil
	}
	ss.evaluateAdaptiveRate(time.Now())
	return ss.limiter.Wait(ctx)
}

func (ss *SynScanner) evaluateAdaptiveRate(now time.Time) {
	if ss.adaptive == nil || !ss.adaptive.beginEvaluation(now) {
		return
	}
	var stats *pcap.Stats
	if ss.pcapStats != nil {
		stats, _ = ss.pcapStats()
	}
	pending := 0
	if ss.watchIpStatusT != nil {
		pending = ss.watchIpStatusT.Len()
	}
	const pendingCapacity = int(synSourcePortMax-synSourcePortMin) + 1
	newRate, reason, changed := ss.adaptive.evaluateClaimed(pending, pendingCapacity, stats)
	if !changed {
		return
	}
	oldRate := int(ss.limiter.Limit())
	applyAdaptiveRate(ss.limiter, now, newRate)
	if ss.option.Debug {
		fmt.Printf("[d] SYN 自适应调速 old_rate=%d new_rate=%d reason=%s pending=%d\n", oldRate, newRate, reason, pending)
	}
}

func (ss *SynScanner) handleProbeTimeout(probe pendingProbe) bool {
	if probe.retried {
		if ss.adaptive != nil {
			ss.adaptive.recordRetry(false)
		}
		return false
	}
	if ss.adaptive == nil || probe.retry == nil || ss.retryChan == nil {
		return false
	}
	probe.retried = true
	probe.sentAt = time.Time{}
	if !ss.watchIpStatusT.RearmProbe(probe) {
		return false
	}
	select {
	case ss.retryChan <- probe:
		return true
	default:
		ss.watchIpStatusT.DropProbe(probe.key)
		return false
	}
}

func (ss *SynScanner) retryLoop() {
	for {
		select {
		case <-ss.ctx.Done():
			return
		case probe := <-ss.retryChan:
			if err := ss.waitGlobalLimiter(probe.context()); err != nil {
				ss.finishRetryError(probe, err)
				continue
			}
			if !ss.watchIpStatusT.TouchProbe(probe.key, time.Now()) {
				continue
			}
			if err := probe.retry(); err != nil {
				if ss.adaptive != nil {
					ss.adaptive.recordWriteError()
				}
				ss.finishRetryError(probe, err)
			}
		}
	}
}

func (ss *SynScanner) finishRetryError(probe pendingProbe, err error) {
	tracked, ok := ss.watchIpStatusT.DropProbe(probe.key)
	if !ok {
		return
	}
	outcome := port.ProbeError
	if tracked.context().Err() != nil || errors.Is(err, context.Canceled) {
		outcome = port.ProbeAborted
	}
	tracked.option.EmitProbeDone(port.ProbeEvent{
		IP:        net.ParseIP(tracked.key.ip),
		Port:      tracked.key.dstPort,
		Outcome:   outcome,
		Err:       err,
		StartedAt: tracked.startedAt,
	})
	tracked.cancelContext()
}

func (ss *SynScanner) waitHostLimiter(ip net.IP) error {
	return ss.waitHostLimiterContext(ss.ctx, ip)
}

func (ss *SynScanner) waitHostLimiterContext(ctx context.Context, ip net.IP) error {
	if ss.hostLimiter == nil || ip == nil {
		return nil
	}
	return ss.hostLimiter.Wait(ctx, ip.String())
}

// GetDevName Get the device name after the route selection
func (ss *SynScanner) GetDevName() string {
	return ss.devName
}

func newHostLimiter(ratePerHost int) hostLimiter {
	return port.NewHostLimiterStore(ratePerHost)
}

func (ss *SynScanner) macResolveTimeout() time.Duration {
	if ss.option.Timeout > 0 {
		return time.Duration(ss.option.Timeout) * time.Millisecond
	}
	return 600 * time.Millisecond
}

func (ss *SynScanner) portProbeHandle() {
	for _openProbe := range ss.openPortChan {
		openProbe := _openProbe
		openIpPort := openProbe.result
		probeCtx := openProbe.probe.ctx
		if probeCtx == nil {
			probeCtx = ss.ctx
		}
		if !openIpPort.FingerPrint && !openIpPort.Httpx {
			_ = port.EmitOpenProbeResult(probeCtx, ss.retChan, openIpPort, openProbe.probe.startedAt)
			openProbe.probe.cancelContext()
			ss.portProbeWg.Done()
		} else {
			if ss.fingerPool.TrySubmit(func() {
				defer func() {
					openProbe.probe.cancelContext()
					ss.portProbeWg.Done()
				}()
				openIpPort := openProbe.result
				fingerTimeout := ss.option.FingerTimeoutDuration()
				fingerCtx, cancel := context.WithTimeout(probeCtx, fingerTimeout)
				defer cancel()
				if openIpPort.Port != 0 {
					// openPortChan already carries a confirmed open port; probe failures only skip enrichment.
					if openIpPort.FingerPrint {
						openIpPort.Service, openIpPort.Banner, _ = fingerprint.PortIdentifyContext(fingerCtx, "tcp", openIpPort.Ip, openIpPort.Port, fingerTimeout)
					}
					if openIpPort.Httpx && (openIpPort.Service == "" || openIpPort.Service == "http" || openIpPort.Service == "https") {
						openIpPort.HttpInfo, openIpPort.Banner, _ = fingerprint.ProbeHttpInfoContext(fingerCtx, openIpPort.Ip.String(), openIpPort.Port, openIpPort.Service, fingerTimeout)
						if openIpPort.HttpInfo != nil {
							if strings.HasPrefix(openIpPort.HttpInfo.Url, "https") {
								openIpPort.Service = "https"
							} else {
								openIpPort.Service = "http"
							}
						}
					}
				}
				_ = port.EmitOpenProbeResult(probeCtx, ss.retChan, openIpPort, openProbe.probe.startedAt)
			}) {
				continue
			}
			openIpPort.Service = "unknown"
			_ = port.EmitOpenProbeResult(probeCtx, ss.retChan, openIpPort, openProbe.probe.startedAt)
			openProbe.probe.cancelContext()
			ss.portProbeWg.Done()
		}
	}
}

func (ss *SynScanner) getHwAddr(arpDst net.IP) (mac net.HardwareAddr, err error) {
	if arpDst.To4() != nil {
		return ss.getHwAddrV4(arpDst)
	} else {
		return ss.getHwAddrV6(arpDst)
	}
}

// getHwAddrV4 get the destination hardware address for our packets.
func (ss *SynScanner) getHwAddrV4(arpDst net.IP) (mac net.HardwareAddr, err error) {
	ipStr := arpDst.String()
	if ss.watchMacCacheT.IsNeedWatch(ipStr) {
		return nil, errors.New("arp of this ip has been in monitoring")
	}
	ss.watchMacCacheT.UpdateLastTime(ipStr) // New one ip watch

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(ss.srcMac),
		SourceProtAddress: []byte(ss.srcIp),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	if err = ss.sendArp(&eth, &arp); err != nil {
		return nil, err
	}

	start := time.Now()
	timeout := ss.macResolveTimeout()
	var retry int

	for {
		if err = ss.ctx.Err(); err != nil {
			return nil, err
		}
		mac = ss.watchMacCacheT.GetMac(ipStr)
		if mac != nil {
			return mac, nil
		}
		// Wait 600 ms for an ARP reply.
		if time.Since(start) > timeout {
			return nil, errors.New("timeout getting ARP reply")
		}
		retry += 1
		if retry%25 == 0 {
			if err = ss.send(&eth, &arp); err != nil {
				return nil, err
			}
		}

		time.Sleep(time.Millisecond * 10)
	}
}

// convertIPv6ToMac converts an IPv6 address that was generated via SLAAC
// to the corresponding MAC address.
func (ss *SynScanner) convertIPv6ToMac(ipv6 net.IP) (net.HardwareAddr, error) {
	if !((ipv6[0] == 0xfe && (ipv6[1]&0xc0 == 0x80)) || // fe80::/10
		(ipv6[0] == 0x20 && ipv6[1] == 0x02) || // 2002::/16
		(ipv6[0] == 0xff)) { // ff00::/8
		return nil, errors.New("no SLAAC adder")
	}

	// Extract the interface identifier from the last 8 bytes of the IPv6 address
	interfaceIdentifier := ipv6[8:16]
	if (interfaceIdentifier[0] & 0x02) != 0x02 {
		return nil, errors.New("no SLAAC adder")
	}

	// Convert EUI-64 to MAC address
	mac := make(net.HardwareAddr, 6)
	copy(mac, interfaceIdentifier[:3])
	copy(mac[3:], interfaceIdentifier[5:])

	// Flip the U/L bit in the first octet of the MAC address
	mac[0] = mac[0] ^ 0x02
	return mac, nil
}

// getHwAddrV6 get the destination hardware address for our packets.
func (ss *SynScanner) getHwAddrV6(arpDst net.IP) (mac net.HardwareAddr, err error) {
	mac, err = ss.convertIPv6ToMac(arpDst)
	if mac != nil {
		return
	}

	ipStr := arpDst.String()
	if ss.watchMacCacheT.IsNeedWatch(ipStr) {
		return nil, errors.New("arp of this ip has been in monitoring")
	}
	ss.watchMacCacheT.UpdateLastTime(ipStr) // New one ip watch

	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       []byte{51, 51, 255, arpDst[13], arpDst[14], arpDst[15]},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      ss.srcIp,
		DstIP:      arpDst,
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	icmpv6Payload := layers.ICMPv6NeighborSolicitation{
		TargetAddress: arpDst,
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: ss.srcMac,
			},
		},
	}

	icmpv6.SetNetworkLayerForChecksum(&ipv6)

	start := time.Now()
	timeout := ss.macResolveTimeout()
	var retry int

	for {
		if err = ss.ctx.Err(); err != nil {
			return nil, err
		}
		mac = ss.watchMacCacheT.GetMac(ipStr)
		if mac != nil {
			return mac, nil
		}
		if time.Since(start) > timeout {
			return nil, errors.New("timeout getting ICMP V6 NA reply")
		}
		retry += 1
		if retry%25 == 0 {
			if err = ss.send(&eth, &ipv6, &icmpv6, &icmpv6Payload); err != nil {
				return nil, err
			}
		}

		time.Sleep(time.Millisecond * 10)
	}
}

// send sends the given layers as a single packet on the network.
func (ss *SynScanner) send(l ...gopacket.SerializableLayer) error {
	buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		buf.Clear()
		ss.bufPool.Put(buf)
	}()
	if err := gopacket.SerializeLayers(buf, ss.opts, l...); err != nil {
		return err
	}
	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()
	if ss.isDone.Load() || ss.handle == nil {
		if ss.ctx != nil {
			if err := ss.ctx.Err(); err != nil {
				return err
			}
		}
		return io.EOF
	}
	return ss.handle.WritePacketData(buf.Bytes())
}

// send sends the given layers as a single packet on the network., need fix padding
func (ss *SynScanner) sendArp(l ...gopacket.SerializableLayer) error {
	buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		buf.Clear()
		ss.bufPool.Put(buf)
	}()
	if err := gopacket.SerializeLayers(buf, ss.opts, l...); err != nil {
		return err
	}
	ss.sendMu.Lock()
	defer ss.sendMu.Unlock()
	if ss.isDone.Load() || ss.handle == nil {
		if ss.ctx != nil {
			if err := ss.ctx.Err(); err != nil {
				return err
			}
		}
		return io.EOF
	}
	return ss.handle.WritePacketData(buf.Bytes()[:42]) // need fix padding
}

// recv packet on the network.
func (ss *SynScanner) recv() {
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       nil,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    ss.srcIp,
		DstIP:    []byte{},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	ip6 := layers.IPv6{
		SrcIP:      ss.srcIp,
		DstIP:      []byte{},
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 0,
		DstPort: 0,
		RST:     true,
		ACK:     true,
		Seq:     1,
	}

	// Decode
	var ipLayer layers.IPv4
	var ipv6Layer layers.IPv6
	var ipv6IcmpLayer layers.ICMPv6
	var ipv6IcmpNALayer layers.ICMPv6NeighborAdvertisement
	var tcpLayer layers.TCP
	var arpLayer layers.ARP
	var ethLayer layers.Ethernet
	var foundLayerTypes []gopacket.LayerType

	// Parse the packet.
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&ipv6Layer,
		&tcpLayer,
		&arpLayer,
		// IPv6 的 NA 位于 ICMPv6 负载中，不能跳过通用 ICMPv6 解码层。
		&ipv6IcmpLayer,
		&ipv6IcmpNALayer,
	)

	// global var
	var err error
	var data []byte
	var ipStr string
	var _port uint16
	var disIp net.IP

	for {
		// Read in the next packet.
		data, _, err = ss.handle.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}

		// is done
		if ss.isDone.Load() {
			return
		}

		// Decode TCP or ARP Packet
		err = parser.DecodeLayers(data, &foundLayerTypes)
		if len(foundLayerTypes) == 0 {
			continue
		}

		// arp
		if arpLayer.SourceProtAddress != nil {
			ipStr = net.IP(arpLayer.SourceProtAddress).String()
			if ss.watchMacCacheT.IsNeedWatch(ipStr) {
				ss.watchMacCacheT.SetMac(ipStr, arpLayer.SourceHwAddress)
			}
			arpLayer.SourceProtAddress = nil // clean arp parse status
			continue
		}

		// IPv6 NA
		if ipv6IcmpNALayer.TargetAddress != nil {
			ss.cacheIPv6NeighborAdvertisement(ipv6IcmpNALayer.TargetAddress, ethLayer.SrcMAC)
			ipv6IcmpNALayer.TargetAddress = nil
			ipv6IcmpNALayer.Options = nil
			continue
		}

		if ethLayer.EthernetType == layers.EthernetTypeIPv6 {
			disIp = ipv6Layer.SrcIP
			ip6.DstIP = disIp
			eth.EthernetType = layers.EthernetTypeIPv6
		} else {
			disIp = ipLayer.SrcIP
			ip4.DstIP = disIp
		}

		// tcp Match ip and port
		if tcpLayer.DstPort != 0 && tcpLayer.DstPort >= 49000 && tcpLayer.DstPort <= 59000 {
			ipStr = disIp.String()
			_port = uint16(tcpLayer.SrcPort)
			srcPort := uint16(tcpLayer.DstPort)
			if tcpLayer.SYN && tcpLayer.ACK {
				ss.portProbeWg.Add(1)
				probe, has := ss.watchIpStatusT.TakeProbe(ipStr, srcPort, _port)
				if !has { // IP/PORT no matching probe
					ss.portProbeWg.Done()
					continue
				}
				if probe.retried && ss.adaptive != nil {
					ss.adaptive.recordRetry(true)
				}
				if !ss.enqueueTrackedOpenPort(synOpenProbe{
					result: port.OpenIpPort{
						Ip:       disIp,
						Port:     _port,
						IpOption: probe.option,
					},
					probe: probe,
				}) {
					probe.option.EmitProbeDone(port.ProbeEvent{
						IP:        disIp,
						Port:      _port,
						Outcome:   port.ProbeAborted,
						StartedAt: probe.startedAt,
					})
					probe.cancelContext()
					return
				}
				// reply to target
				eth.DstMAC = ethLayer.SrcMAC
				tcp.DstPort = tcpLayer.SrcPort
				tcp.SrcPort = tcpLayer.DstPort
				// RST && ACK
				tcp.Ack = tcpLayer.Seq + 1
				tcp.Seq = tcpLayer.Ack
				if ethLayer.EthernetType == layers.EthernetTypeIPv6 {
					tcp.SetNetworkLayerForChecksum(&ip6)
					ss.send(&eth, &ip6, &tcp)
				} else {
					tcp.SetNetworkLayerForChecksum(&ip4)
					ss.send(&eth, &ip4, &tcp)
				}
			} else if tcpLayer.RST {
				probe, has := ss.watchIpStatusT.TakeProbe(ipStr, srcPort, _port)
				if !has { // IP/PORT no matching probe
					continue
				}
				if probe.retried && ss.adaptive != nil {
					ss.adaptive.recordRetry(true)
				}
				probe.option.EmitProbeDone(port.ProbeEvent{
					IP:        disIp,
					Port:      _port,
					Outcome:   port.ProbeClosed,
					StartedAt: probe.startedAt,
				})
				probe.cancelContext()
			}
			tcpLayer.DstPort = 0 // clean tcp parse status
		}
	}
}

func (ss *SynScanner) enqueueOpenPort(openProbe synOpenProbe) bool {
	if ss.ctx.Err() != nil {
		return false
	}
	ss.portProbeWg.Add(1)
	return ss.enqueueTrackedOpenPort(openProbe)
}

func (ss *SynScanner) enqueueTrackedOpenPort(openProbe synOpenProbe) bool {
	if ss.ctx.Err() != nil {
		ss.portProbeWg.Done()
		return false
	}
	select {
	// recv feeds the enrichment stage through this queue; make it cancellation-aware for shutdown.
	case ss.openPortChan <- openProbe:
		return true
	case <-ss.ctx.Done():
		ss.portProbeWg.Done()
		return false
	}
}

func (ss *SynScanner) cacheIPv6NeighborAdvertisement(target net.IP, sourceMAC net.HardwareAddr) {
	if ss.watchMacCacheT == nil || target == nil || len(sourceMAC) == 0 {
		return
	}
	ipStr := target.String()
	if ss.watchMacCacheT.IsNeedWatch(ipStr) {
		ss.watchMacCacheT.SetMac(ipStr, sourceMAC)
	}
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
