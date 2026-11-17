package socks5

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/Li-giegie/open-proxy/internal/netutil"
)

// Options 是创建 Proxy 的配置，零值字段使用各自的默认值。
type Options struct {
	// Authenticator 为代理认证器；nil 表示开放代理（只接受无认证方法）。
	Authenticator Authenticator
	// DialTimeout 为连接目标的超时时间。
	DialTimeout time.Duration
	// IdleTimeout 为 CONNECT 隧道单方向无数据的超时时间，超时断开隧道。
	IdleTimeout time.Duration
	// Logger 为请求与错误日志；nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// Proxy 是 SOCKS5 正向代理：
//   - 认证方式由 Authenticator 决定（默认提供 RFC 1929 用户名/密码实现）；
//   - 代理命令只实现 CONNECT，BIND 与 UDP ASSOCIATE 返回 COMMAND NOT SUPPORTED；
//   - 地址类型支持 IPv4、IPv6 与域名（由代理代为解析后拨号）。
//
// Close 关闭监听与全部活动连接，Serve 随之返回。
type Proxy struct {
	authenticator Authenticator
	dialer        *net.Dialer
	idleTimeout   time.Duration
	logger        *slog.Logger

	// mu 保护生命周期状态：ln/conns/closed
	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
}

// New 按配置创建 Proxy。
func New(opts Options) (*Proxy, error) {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 2 * time.Minute
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Proxy{
		authenticator: opts.Authenticator,
		dialer: &net.Dialer{
			Timeout:   opts.DialTimeout,
			KeepAlive: 30 * time.Second,
		},
		idleTimeout: opts.IdleTimeout,
		logger:      logger,
	}, nil
}

// Serve 在 ln 上接受连接并逐个处理，直到 Close 或监听关闭。
func (p *Proxy) Serve(ln net.Listener) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	p.ln = ln
	p.conns = map[net.Conn]struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.ln = nil
		p.mu.Unlock()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go p.handleConn(conn)
	}
}

// Close 关闭监听与全部活动连接（含 CONNECT 隧道），Serve 随之返回。
// 重复调用为幂等。
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	ln := p.ln
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return err
}

// trackConn / untrackConn 登记活动连接，供 Close 一并断开。
func (p *Proxy) trackConn(conn net.Conn) {
	p.mu.Lock()
	if p.conns != nil {
		p.conns[conn] = struct{}{}
	}
	p.mu.Unlock()
}

func (p *Proxy) untrackConn(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

// handleConn 处理一条客户端连接的完整生命周期：
// 认证协商 → （可选）用户名/密码子协商 → 代理请求 → 拨号 → 双向透传。
func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()
	p.trackConn(conn)
	defer p.untrackConn(conn)

	auth, err := ReadAuth(context.Background(), conn, nil)
	if err != nil {
		p.logger.Warn("read auth failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}
	if auth.Version != 5 {
		p.logger.Warn("version mismatch", "remote", conn.RemoteAddr(), "version", auth.Version)
		return
	}

	// 选择认证方法：配置了认证器只接受用户名/密码，否则只接受无认证
	var selected Method
	if p.authenticator != nil {
		selected = MethodUserPass
	} else {
		selected = MethodNoAuth
	}
	if !auth.hasMethod(selected) {
		p.logger.Warn("no acceptable auth method", "remote", conn.RemoteAddr(), "methods", auth.Methods)
		// 必须先回应 NoAcceptableMethods 再关闭，客户端才能区分
		// "方法不支持"与"连接故障"
		_, _ = (&AuthResponse{Version: 5, Methods: MethodNoAcceptableMethods}).Write(conn, nil)
		return
	}
	if _, err := (&AuthResponse{Version: 5, Methods: selected}).Write(conn, nil); err != nil {
		p.logger.Warn("write auth response failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}

	// 用户名/密码子协商（RFC 1929），失败即断开
	if p.authenticator != nil {
		up, err := ReadUserPassRequest(context.Background(), conn, nil)
		if err != nil {
			p.logger.Warn("read userpass failed", "remote", conn.RemoteAddr(), "error", err)
			return
		}
		resp := &UserPassResponse{Version: 1}
		if p.authenticator.Authenticate(up.Username, up.Password) {
			resp.Status = UserPassResponseStatusSuccess
		} else {
			resp.Status = UserPassResponseStatusFail
		}
		if _, err := resp.Write(conn, nil); err != nil {
			p.logger.Warn("write userpass response failed", "remote", conn.RemoteAddr(), "error", err)
			return
		}
		if resp.Status != UserPassResponseStatusSuccess {
			p.logger.Warn("auth failed", "remote", conn.RemoteAddr(), "user", up.Username)
			return
		}
		p.logger.Info("auth ok", "remote", conn.RemoteAddr(), "user", up.Username)
	}

	req, err := ReadRequest(context.Background(), conn, nil)
	if err != nil {
		p.logger.Warn("read request failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}
	if req.Version != 5 {
		p.logger.Warn("version mismatch", "remote", conn.RemoteAddr(), "version", req.Version)
		return
	}

	switch req.Command {
	case CommandConnect:
		p.handleConnect(conn, req)
	case CommandBind, CommandAssociate:
		// 未实现：BIND/UDP ASSOCIATE 均按规范返回 COMMAND NOT SUPPORTED
		p.logger.Info("command not supported", "remote", conn.RemoteAddr(), "cmd", req.Command)
		p.reply(conn, req, ReplyCommandNotSupported)
	default:
		p.logger.Warn("unknown command", "remote", conn.RemoteAddr(), "cmd", req.Command)
		p.reply(conn, req, ReplyCommandNotSupported)
	}
}

// handleConnect 处理 CONNECT：拨号目标成功后回应 SUCCEEDED 并双向透传。
func (p *Proxy) handleConnect(conn net.Conn, req *Request) {
	p.logger.Info("connect", "remote", conn.RemoteAddr(), "target", net.JoinHostPort(req.Addr, fmt.Sprint(req.Port)))

	dst, err := p.dialer.Dial("tcp", net.JoinHostPort(req.Addr, fmt.Sprint(req.Port)))
	if err != nil {
		p.logger.Warn("connect target failed", "remote", conn.RemoteAddr(),
			"target", req.Addr, "error", err)
		p.reply(conn, req, replyOf(err))
		return
	}
	defer dst.Close()

	if err := p.reply(conn, req, ReplySucceeded); err != nil {
		p.logger.Warn("write response failed", "remote", conn.RemoteAddr(), "error", err)
		return
	}

	// 双向透传，直到两个方向都结束。单个方向结束后只半关闭对端的写侧
	// （发送 FIN），让另一个方向可以把剩余数据传完
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		netutil.CopyStream(dst, conn, p.idleTimeout, nil) // 客户端 → 目标
		netutil.CloseWrite(dst)
	}()
	go func() {
		defer wg.Done()
		netutil.CopyStream(conn, dst, p.idleTimeout, nil) // 目标 → 客户端
		netutil.CloseWrite(conn)
	}()
	wg.Wait()
}

// reply 向客户端写请求响应。BND.ADDR/BND.PORT 按惯例回报代理本端地址
// （客户端通常忽略），写失败时由调用方决定是否断开。
func (p *Proxy) reply(conn net.Conn, req *Request, reply Reply) error {
	resp := &Response{Version: req.Version, Reply: reply}
	if reply == ReplySucceeded {
		host, portStr, err := net.SplitHostPort(dstLocalAddr(conn))
		if err == nil {
			resp.Addr = host
			resp.Port = uint16(atoi(portStr))
		}
	}
	_, err := resp.Write(conn, nil)
	return err
}

// dstLocalAddr 返回响应里回报的地址：拨号成功后客户端连接的本地地址
// 反映了目标路径上实际使用的源地址，无 TCP 信息时退化为 unspecified。
func dstLocalAddr(conn net.Conn) string {
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return net.JoinHostPort(addr.IP.String(), fmt.Sprint(addr.Port))
	}
	return "0.0.0.0:0"
}

// hasMethod 报告客户端是否提供了指定方法。
func (a *AuthRequest) hasMethod(m Method) bool {
	return slices.Contains(a.Methods, m)
}

// Windows 的 WSA errno。syscall.E* 常量在 Windows 上是不可被网络栈产生
// 的伪值，拨号错误须按 WSA 数值兜底匹配（Linux/macOS 上 syscall.E* 直接相等）。
const (
	wsaECONNREFUSED = 10061 // WSAECONNREFUSED
	wsaETIMEDOUT    = 10060 // WSAETIMEDOUT
	wsaEHOSTUNREACH = 10065 // WSAEHOSTUNREACH
	wsaENETUNREACH  = 10051 // WSAENETUNREACH
)

// replyOf 把拨号错误映射为 SOCKS5 回复码。
func replyOf(err error) Reply {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		// 工程惯例：TTL_EXPIRED 表示连接超时
		return ReplyTTLExpired
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReplyHostUnreachable // DNS 解析失败
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED, wsaECONNREFUSED:
			return ReplyConnectionRefused
		case syscall.ETIMEDOUT, wsaETIMEDOUT:
			return ReplyTTLExpired
		case syscall.EHOSTUNREACH, wsaEHOSTUNREACH:
			return ReplyHostUnreachable
		case syscall.ENETUNREACH, wsaENETUNREACH:
			return ReplyNetworkUnreachable
		}
	}
	return ReplyGeneralServerFailure
}

// atoi 是 strconv.Atoi 的窄化包装，失败返回 0（SplitHostPort 成功后
// 端口必然是数字，失败路径由调用方兜底为 unspecified 地址）。
func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
