package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options 是创建 Proxy 的配置，零值字段使用各自的默认值。
type Options struct {
	// Authenticator 为代理认证器；nil 表示开放代理（不认证）。
	Authenticator Authenticator
	// DialTimeout 为连接上游 TCP 的超时时间，也用于与上游代理的
	// TLS 握手及 CONNECT 响应。
	DialTimeout time.Duration
	// TunnelIdleTimeout 为 CONNECT 隧道单方向无数据的超时时间，超时断开隧道。
	TunnelIdleTimeout time.Duration
	// Logger 为请求与错误日志；nil 时使用 slog.Default()。
	Logger *slog.Logger
	// Upstream 为上游正向代理 URL；设置后所有出站流量（HTTP 转发与
	// CONNECT 隧道）先经该代理转发，形成代理链。URL 的 userinfo 用作
	// 对上游的 Basic 认证（如 http://user:pass@host:port）。
	Upstream *url.URL
	// UpstreamTLS 为与上游代理 TLS 握手的客户端配置，仅对 https 上游生效：
	// RootCAs 校验上游证书（nil 时信任系统根证书），Certificates 为 mTLS
	// 时出示的客户端证书。
	UpstreamTLS *tls.Config
	// Metrics 收集运行指标（请求数、状态码、双向字节数），nil 表示不收集。
	Metrics Metrics
}

// Metrics 收集代理运行指标，所有方法必须并发安全，nil 语义由 Proxy
// 内部以空实现兜底。实现方应假设每个方法都被高频调用。
type Metrics interface {
	// Request 记录一次通过认证的代理请求（普通转发或 CONNECT 隧道）。
	//   url 为请求目标（普通请求是绝对 URL，CONNECT 是 host:port）；
	//   user 为认证用户名，未启用认证时为空。
	Request(user, method, url string)
	// Response 记录转发结果状态码（CONNECT 以隧道建立结果为准）。
	Response(status int)
	// BytesIn 记录客户端 → 目标方向的字节数。
	BytesIn(n int64)
	// BytesOut 记录目标 → 客户端方向的字节数。
	BytesOut(n int64)
}

// noopMetrics 是 Metrics 的空实现。
type noopMetrics struct{}

func (noopMetrics) Request(string, string, string) {}
func (noopMetrics) Response(int)                   {}
func (noopMetrics) BytesIn(int64)                  {}
func (noopMetrics) BytesOut(int64)                 {}

// countingReader 统计读出的字节数（请求体方向），Close 透传给底层。
type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error {
	return c.r.Close()
}

// Proxy 是 HTTP/HTTPS 正向代理：
//   - 普通 HTTP 请求原样转发到上游，响应头完整回传；
//   - CONNECT 请求与上游建立 TCP 连接后做双向透传；
//   - 认证方式由 Authenticator 决定（默认提供 Basic 实现，UserStore
//     支持动态增删用户）；
//   - 配置 Upstream 时所有出站流量先经上游代理转发（代理链）；
//   - 配置 Metrics 时收集请求数与双向字节数。
type Proxy struct {
	authenticator Authenticator
	client        *http.Client
	// dial 建立到目标的传输通道：直连，或经上游代理的 CONNECT 隧道。
	dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	idleTimeout time.Duration
	logger      *slog.Logger
	metrics     Metrics
}

// New 按配置创建 Proxy。Upstream 非法（scheme 不是 http/https）时返回错误。
func New(opts Options) (*Proxy, error) {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.TunnelIdleTimeout <= 0 {
		opts.TunnelIdleTimeout = 2 * time.Minute
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	dialer := &net.Dialer{
		Timeout:   opts.DialTimeout,
		KeepAlive: 30 * time.Second,
	}

	dial := dialer.DialContext
	if opts.Upstream != nil {
		var err error
		dial, err = newUpstreamDialer(opts.Upstream, opts.UpstreamTLS, dialer, opts.DialTimeout)
		if err != nil {
			return nil, err
		}
	}

	// DisableCompression 关闭 Transport 的透明 gzip 解压：客户端自己声明的
	// Accept-Encoding 原样透传，上游返回什么就转发什么，避免响应头与
	// 正文编码不一致。
	//
	// 代理链模式下 DialContext 换成经上游的隧道拨号：对 https 目标，
	// Transport 在隧道内直接与目标做端到端 TLS 握手（目标证书按系统根
	// 证书校验，与上游 TLS 配置互不影响）。
	transport := &http.Transport{
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Proxy{
		authenticator: opts.Authenticator,
		dial:          dial,
		idleTimeout:   opts.TunnelIdleTimeout,
		logger:        logger,
		metrics:       metricsOrNoop(opts.Metrics),
		client: &http.Client{
			Transport: transport,
			// 代理不代替客户端跟随重定向，3xx 原样透传
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func metricsOrNoop(m Metrics) Metrics {
	if m == nil {
		return noopMetrics{}
	}
	return m
}

// ServeHTTP 先做代理认证，再按 CONNECT / 普通 HTTP 分流。
func (p *Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if p.authenticator != nil && !p.authenticator.Authenticate(req) {
		p.logger.Warn("auth failed", "remote", req.RemoteAddr)
		if challenge := p.authenticator.Challenge(); challenge != "" {
			rw.Header().Set("Proxy-Authenticate", challenge)
		}
		http.Error(rw, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	// 认证用户名（未认证或认证器不提供时为空），供指标归属
	var user string
	if un, ok := p.authenticator.(interface{ User(*http.Request) string }); ok {
		user = un.User(req)
	}
	p.logger.Info("request", "method", req.Method, "url", req.URL.Redacted(), "remote", req.RemoteAddr, "user", user)
	p.metrics.Request(user, req.Method, requestTarget(req))

	switch {
	case req.Method == http.MethodConnect:
		p.handleConnect(rw, req)
	case req.URL.IsAbs():
		p.handleForward(rw, req)
	default:
		// 正向代理收到的请求必须是绝对 URL 形式
		http.Error(rw, "absolute URL required: this is a forward proxy", http.StatusBadRequest)
	}
}

// requestTarget 返回请求目标：普通请求为绝对 URL，CONNECT 为 host:port。
func requestTarget(req *http.Request) string {
	if req.Method == http.MethodConnect {
		return req.URL.Host
	}
	return req.URL.String()
}

// handleForward 转发普通 HTTP 请求：剔除逐跳头后把请求原样发给上游，
// 上游响应头（同样剔除逐跳头后）完整回传给客户端，重定向由客户端自行处理。
func (p *Proxy) handleForward(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		http.Error(rw, "unsupported protocol scheme: "+req.URL.Scheme, http.StatusBadRequest)
		return
	}

	// RequestURI 是服务端解析出的字段，http.Client 不允许请求携带它
	req.RequestURI = ""

	removeHopByHopHeaders(req.Header)

	// 上游看到的是代理发起的请求，补充客户端来源信息（保留链路上已有的记录）
	if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			ip = prior + ", " + ip
		}
		req.Header.Set("X-Forwarded-For", ip)
	}

	// 请求体经计数包装，转发完成后上报客户端 → 目标方向字节数
	body := &countingReader{r: req.Body}
	req.Body = body

	resp, err := p.client.Do(req)
	p.metrics.BytesIn(body.n)
	if err != nil {
		p.logger.Warn("forward failed", "url", req.URL.Redacted(), "error", err)
		http.Error(rw, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		p.metrics.Response(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	p.metrics.Response(resp.StatusCode)

	removeHopByHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, v := range values {
			rw.Header().Add(key, v)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(rw, resp.Body)
	p.metrics.BytesOut(n)
}

// handleConnect 处理 CONNECT 请求：与上游建立 TCP 连接后，把客户端连接劫持
// 出来做双向透传，此后代理不再介入隧道内的内容（如 TLS 握手）。
func (p *Proxy) handleConnect(rw http.ResponseWriter, req *http.Request) {
	// CONNECT 的请求目标是 authority 形式（host:port），Go 已解析进 URL.Host
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if host == "" {
		http.Error(rw, "missing target host", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		// 未带端口时默认按 HTTPS 处理。这里用 SplitHostPort 判断而不是
		// strings.Contains，避免把 IPv6 字面量 [::1] 误判为已带端口。
		host = net.JoinHostPort(host, "443")
	}

	dst, err := p.dial(req.Context(), "tcp", host)
	if err != nil {
		http.Error(rw, "connect failed: "+err.Error(), http.StatusBadGateway)
		p.metrics.Response(http.StatusBadGateway)
		return
	}
	defer dst.Close()

	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		http.Error(rw, "hijack not supported", http.StatusInternalServerError)
		return
	}
	// Hijack 之后连接由代理接管，无法再通过 rw 写响应
	src, brw, err := hijacker.Hijack()
	if err != nil {
		http.Error(rw, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer src.Close()

	// 向客户端确认隧道建立成功
	if _, err := brw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	if err := brw.Flush(); err != nil {
		return
	}
	p.metrics.Response(http.StatusOK)

	// brw.Reader 中可能已缓存客户端在收到确认前抢先发来的字节（如
	// TLS ClientHello），必须先转交给上游，之后才能直接用底层连接拷贝
	for brw.Reader.Buffered() > 0 {
		buf := make([]byte, brw.Reader.Buffered())
		if _, err := io.ReadFull(brw.Reader, buf); err != nil {
			return
		}
		if _, err := dst.Write(buf); err != nil {
			return
		}
		p.metrics.BytesIn(int64(len(buf)))
	}

	// 双向透传，直到两个方向都结束。单个方向结束后只半关闭对端的写侧
	// （发送 FIN），让另一个方向可以把剩余数据传完。字节逐块上报，
	// 活跃隧道在监控里也能实时看到流量，而不是断开时一次性结算。
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.copyStream(dst, src, p.metrics.BytesIn) // 客户端 → 上游
		closeWrite(dst)
	}()
	go func() {
		defer wg.Done()
		p.copyStream(src, dst, p.metrics.BytesOut) // 上游 → 客户端
		closeWrite(src)
	}()
	wg.Wait()
}

// copyStream 从 src 单向拷贝到 dst，每块数据写出后调用 count 上报。
// 每次读写都把超时刷新到 idleTimeout 之后，长时间无数据流动即超时
// 断开，避免连接被慢速客户端永久占用。
func (p *Proxy) copyStream(dst, src net.Conn, count func(int64)) {
	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(p.idleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(p.idleTimeout))
			if _, err = dst.Write(buf[:n]); err != nil {
				return
			}
			count(int64(n))
		}
		if err != nil {
			// io.EOF 为对端正常结束，其余为连接错误或空闲超时
			return
		}
	}
}

// newUpstreamDialer 返回经上游正向代理建立隧道的拨号函数（代理链）：
// 先连上游（https 时做 TLS 握手），再向上游发 CONNECT 建立到 addr 的
// 隧道，此后该连接对调用方就是一条到 addr 的裸管道。对上游的 Basic
// 认证取自 upstream URL 的 userinfo，仅在这一跳的 CONNECT 上携带。
func newUpstreamDialer(upstream *url.URL, tlsConf *tls.Config, dialer *net.Dialer, timeout time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" {
		return nil, fmt.Errorf("无效的上游代理 %q（需要形如 http://host:port 或 https://host:port）", upstream)
	}
	host := upstream.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		// 未带端口时按 scheme 补默认端口
		port := "80"
		if upstream.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(host, port)
	}
	serverName := upstream.Hostname()

	var proxyAuth string
	if upstream.User != nil {
		password, _ := upstream.User.Password()
		proxyAuth = "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(upstream.User.Username()+":"+password))
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, fmt.Errorf("连接上游代理 %s: %w", host, err)
		}

		if upstream.Scheme == "https" {
			cfg := &tls.Config{MinVersion: tls.VersionTLS12}
			if tlsConf != nil {
				cfg = tlsConf.Clone()
			}
			if cfg.ServerName == "" {
				cfg.ServerName = serverName
			}
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("与上游代理 %s TLS 握手: %w", host, err)
			}
			conn = tlsConn
		}

		// TLS 握手、CONNECT 写入与响应读取共用一个整体超时
		conn.SetDeadline(time.Now().Add(timeout))

		connectReq := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
		if proxyAuth != "" {
			connectReq += "Proxy-Authorization: " + proxyAuth + "\r\n"
		}
		connectReq += "\r\n"
		if _, err := conn.Write([]byte(connectReq)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("向上游代理发 CONNECT: %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("读取上游代理 CONNECT 响应: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			conn.Close()
			return nil, fmt.Errorf("上游代理拒绝 CONNECT %s: %s", addr, resp.Status)
		}

		conn.SetDeadline(time.Time{})
		return &bufferedConn{Conn: conn, r: br}, nil
	}, nil
}

// bufferedConn 优先返回 bufio.Reader 中已缓冲的字节，用于 CONNECT 响应
// 之后连接里可能已经到达的数据，避免被 bufio 缓冲吞掉。
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// hopByHopHeaders 是逐跳（hop-by-hop）头部（RFC 9110 §7.6.1）及代理专属头部，
// 只在客户端与代理这一跳有意义，转发前必须剔除。
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders 原地剔除逐跳头部。Connection 头里点名的头部
// （如 "Connection: My-Header"）按规范也应一并剔除。
func removeHopByHopHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// closeWrite 半关闭连接的写侧（向对端发送 FIN）。非 TCP 连接不支持
// 半关闭时退化为整条关闭。
func closeWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = c.Close()
}
