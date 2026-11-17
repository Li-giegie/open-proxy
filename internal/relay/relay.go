// Package relay 实现 TCP 中继：监听本地端口，把流量原样转发到配置的
// 上游地址，不解析任何协议。多上游按权重随机选择，拨号失败自动
// failover 换下一个上游（仅拨号阶段重试，透传阶段不重试）；本地监听端
// 与上游端均支持 TLS/mTLS，可经 JSON 配置文件或程序化 Options 构造。
package relay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/Li-giegie/open-proxy/internal/netutil"
)

// upstream 是解析后的单个上游：配置加上构建好的出站 TLS 配置。
type upstream struct {
	address string
	weight  int
	tlsConf *tls.Config
}

// Upstream 是程序化配置的单个上游：地址、权重与已构建的出站 TLS 配置。
type Upstream struct {
	Address string
	Weight  int
	TLS     *tls.Config
}

// Options 是程序化构造 Relay 的配置，TLS 为已构建的 *tls.Config
// （管理中心以 PEM 内容构建后走这里；CLI 文件路径版 New 在内部转换）。
// 零值字段使用各自的默认值。
type Options struct {
	Listen      string
	ListenTLS   *tls.Config
	Upstreams   []Upstream
	DialTimeout time.Duration
	IdleTimeout time.Duration
	Logger      *slog.Logger
}

// Relay 是裸 TCP 中继：把本地连接的字节流原样转发到按权重选择的上游。
// 上游拨号失败时自动 failover 到其余上游，全部失败才断开客户端。
// Close 关闭监听与全部活动连接，Serve 随之返回。
type Relay struct {
	listenAddr  string
	listenTLS   *tls.Config
	upstreams   []upstream
	dialTimeout time.Duration
	idleTimeout time.Duration
	logger      *slog.Logger

	// mu 保护以下字段：ln/conns/closed 是生命周期状态，
	// failedUp 记录最近一轮拨号失败的上游地址（下一轮选择时排到
	// 候选末尾，连续故障场景倾向健康上游）
	mu       sync.Mutex
	ln       net.Listener
	conns    map[net.Conn]struct{}
	closed   bool
	failedUp map[string]struct{}
}

// NewWithOptions 按程序化配置创建 Relay。
func NewWithOptions(opts Options) (*Relay, error) {
	if len(opts.Upstreams) == 0 {
		return nil, errors.New("至少需要一个上游")
	}
	if opts.Listen == "" {
		return nil, errors.New("listen 不能为空")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 2 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	ups := make([]upstream, 0, len(opts.Upstreams))
	for i, u := range opts.Upstreams {
		if u.Address == "" {
			return nil, fmt.Errorf("upstreams[%d].address 不能为空", i)
		}
		if u.Weight < 1 {
			u.Weight = 1
		}
		ups = append(ups, upstream{address: u.Address, weight: u.Weight, tlsConf: u.TLS})
	}

	return &Relay{
		listenAddr:  opts.Listen,
		listenTLS:   opts.ListenTLS,
		upstreams:   ups,
		dialTimeout: opts.DialTimeout,
		idleTimeout: opts.IdleTimeout,
		logger:      opts.Logger,
		failedUp:    map[string]struct{}{},
	}, nil
}

// New 按 JSON 配置文件格式创建 Relay（证书字段为文件路径）。
// 内部转换为 Options 后走 NewWithOptions。
func New(cfg *Config) (*Relay, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dialTimeout, err := cfg.dialTimeout()
	if err != nil {
		return nil, err
	}
	idleTimeout, err := cfg.idleTimeout()
	if err != nil {
		return nil, err
	}

	opts := Options{
		Listen:      cfg.Listen,
		DialTimeout: dialTimeout,
		IdleTimeout: idleTimeout,
	}

	if cfg.ListenTLS != nil {
		opts.ListenTLS, err = netutil.ServerTLS(cfg.ListenTLS.Cert, cfg.ListenTLS.Key, cfg.ListenTLS.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("配置监听端 TLS: %w", err)
		}
	}

	for _, uc := range cfg.Upstreams {
		u := Upstream{Address: uc.Address, Weight: uc.Weight}
		if uc.TLS != nil {
			u.TLS, err = netutil.ClientTLS(uc.TLS.CA, uc.TLS.Cert, uc.TLS.Key)
			if err != nil {
				return nil, fmt.Errorf("配置上游 %s TLS: %w", uc.Address, err)
			}
		}
		opts.Upstreams = append(opts.Upstreams, u)
	}
	return NewWithOptions(opts)
}

// SetLogger 替换日志器（默认 slog.Default()）。
func (r *Relay) SetLogger(l *slog.Logger) {
	if l != nil {
		r.logger = l
	}
}

// ListenAndServe 监听配置地址并开始转发，直到 Close 或监听被关闭。
func (r *Relay) ListenAndServe() error {
	ln, err := net.Listen("tcp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", r.listenAddr, err)
	}
	r.logger.Info("relay listening",
		"address", r.listenAddr,
		"upstreams", len(r.upstreams),
		"tls", r.listenTLS != nil,
		"mtls", r.listenTLS != nil && r.listenTLS.ClientAuth == tls.RequireAndVerifyClientCert,
	)
	return r.Serve(ln)
}

// Serve 在 ln 上接受连接并转发（ListenTLS 非空时自动包成 TLS 监听），
// Close 或监听关闭后返回 nil。
func (r *Relay) Serve(ln net.Listener) error {
	if r.listenTLS != nil {
		ln = tls.NewListener(ln, r.listenTLS)
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	r.ln = ln
	r.conns = map[net.Conn]struct{}{}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.ln = nil
		r.mu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go r.handleConn(conn)
	}
}

// Close 关闭监听与全部活动连接（Stop 语义：立即断开），Serve 随之返回。
// 重复调用为幂等。
func (r *Relay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	ln := r.ln
	conns := make([]net.Conn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return err
}

// handleConn 处理一条客户端连接：加权选上游 → 拨号（失败 failover）→
// 双向透传。
func (r *Relay) handleConn(conn net.Conn) {
	defer conn.Close()
	r.trackConn(conn)
	defer r.untrackConn(conn)

	dst := r.dialWithFailover()
	if dst == nil {
		r.logger.Warn("all upstreams failed", "remote", conn.RemoteAddr())
		return
	}
	defer dst.Close()

	// 双向透传，直到两个方向都结束。单个方向结束后只半关闭对端的写侧
	// （发送 FIN），让另一个方向可以把剩余数据传完
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		netutil.CopyStream(dst, conn, r.idleTimeout, nil) // 客户端 → 上游
		netutil.CloseWrite(dst)
	}()
	go func() {
		defer wg.Done()
		netutil.CopyStream(conn, dst, r.idleTimeout, nil) // 上游 → 客户端
		netutil.CloseWrite(conn)
	}()
	wg.Wait()
}

// trackConn / untrackConn 登记活动连接，供 Close 一并断开。
func (r *Relay) trackConn(conn net.Conn) {
	r.mu.Lock()
	if r.conns != nil {
		r.conns[conn] = struct{}{}
	}
	r.mu.Unlock()
}

func (r *Relay) untrackConn(conn net.Conn) {
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

// dialWithFailover 加权选择并拨号一个可用上游：失败时把该上游从本轮
// 候选中剔除，换下一个继续试，全部失败返回 nil。
func (r *Relay) dialWithFailover() net.Conn {
	candidates := r.orderedCandidates()
	for len(candidates) > 0 {
		idx := pickWeighted(candidates)
		u := candidates[idx]
		conn, err := r.dial(u)
		if err != nil {
			r.logger.Warn("upstream failed, failing over",
				"upstream", u.address, "error", err,
				"remaining", len(candidates)-1)
			r.rememberFailure(u.address)
			candidates = slices.Delete(candidates, idx, idx+1)
			continue
		}
		r.forgetFailure(u.address)
		return conn
	}
	return nil
}

// dial 连接单个上游：明文走 net.Dialer，TLS 走 tls.DialWithDialer
// （自动以地址 host 作 ServerName 校验上游证书）。
func (r *Relay) dial(u upstream) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: r.dialTimeout, KeepAlive: 30 * time.Second}
	if u.tlsConf != nil {
		return tls.DialWithDialer(dialer, "tcp", u.address, u.tlsConf)
	}
	return dialer.Dial("tcp", u.address)
}

// orderedCandidates 返回候选上游：最近拨号失败的排到末尾。同轮 failover
// 已按剔除处理，这里让下一轮连接也倾向健康的上游。
func (r *Relay) orderedCandidates() []upstream {
	r.mu.Lock()
	failed := make(map[string]struct{}, len(r.failedUp))
	for k := range r.failedUp {
		failed[k] = struct{}{}
	}
	r.mu.Unlock()

	healthy := make([]upstream, 0, len(r.upstreams))
	var sick []upstream
	for _, u := range r.upstreams {
		if _, ok := failed[u.address]; ok {
			sick = append(sick, u)
		} else {
			healthy = append(healthy, u)
		}
	}
	return append(healthy, sick...)
}

// rememberFailure / forgetFailure 维护最近失败的上游地址集合。
func (r *Relay) rememberFailure(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failedUp[addr] = struct{}{}
}

func (r *Relay) forgetFailure(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failedUp, addr)
}

// pickWeighted 在候选中按权重随机选一个，返回其下标。
func pickWeighted(candidates []upstream) int {
	total := 0
	for _, u := range candidates {
		total += u.weight
	}
	n := rand.IntN(total)
	for i, u := range candidates {
		n -= u.weight
		if n < 0 {
			return i
		}
	}
	return len(candidates) - 1
}
