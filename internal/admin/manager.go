// Package admin 是 open-proxy 的管理中心：以 Web UI + REST API 的方式
// 创建和管理代理资源（forward / reverse / relay / socks5）。资源以进程内
// 实例运行（http 类资源为 http.Server，relay/socks5 为各自的 TCP 服务），
// 配置持久化到 JSON 文件，重启后自动恢复。
//
// 这是一个独立模块：只依赖 internal/httpproxy、internal/reverseproxy、
// internal/relay、internal/socks5 和 internal/netutil，不反向依赖 cmd 层。
package admin

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Li-giegie/open-proxy/internal/certgen"
	"github.com/Li-giegie/open-proxy/internal/httpproxy"
	"github.com/Li-giegie/open-proxy/internal/netutil"
	"github.com/Li-giegie/open-proxy/internal/relay"
	"github.com/Li-giegie/open-proxy/internal/reverseproxy"
	"github.com/Li-giegie/open-proxy/internal/socks5"
)

// 资源运行状态。
const (
	StatusRunning = "running"
	StatusStopped = "stopped"
	StatusError   = "error"
)

// inst 是一个正在运行的资源实例。
type inst struct {
	ln   net.Listener
	stop func() error // 停止实例：断开监听与全部活动连接
}

// runner 是资源构造出的可运行形态：serve 阻塞式在给定 listener 上服务
// （各类型自行处理监听端 TLS），stop 断开监听与全部连接。http 类资源
// 包一层 http.Server；relay/socks5 直接用各自的 TCP 服务。
type runner struct {
	serve func(ln net.Listener) error
	stop  func() error
}

// Manager 管理所有代理资源的生命周期。所有方法可并发调用。
type Manager struct {
	mu     sync.Mutex
	store  *Store
	res    map[string]*Resource
	inst   map[string]*inst
	status map[string]string // id → stopped/error（running 由 inst 推导）
	errMsg map[string]string
	// userStores 是运行中正向代理的动态用户存储，增删用户即时生效。
	userStores map[string]*httpproxy.UserStore
	// metrics 是资源级运行指标（重启进程后清零）。
	metrics map[string]*resourceMetrics
	// certs 是证书模块的持久化状态（生成的 CA 与签发的证书）。
	certs  *certState
	logger *slog.Logger
}

// NewManager 创建管理中心并加载持久化的资源，逐个尝试启动
// （端口被占等失败的资源标记为 error，不影响其余资源）。
func NewManager(store *Store, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	saved, err := store.Load()
	if err != nil {
		return nil, err
	}
	certs, err := loadCertState(NewCertStore(certStoreDefaultPath(store.path)))
	if err != nil {
		return nil, err
	}
	m := &Manager{
		store:      store,
		res:        make(map[string]*Resource, len(saved)),
		inst:       map[string]*inst{},
		status:     map[string]string{},
		errMsg:     map[string]string{},
		userStores: map[string]*httpproxy.UserStore{},
		metrics:    map[string]*resourceMetrics{},
		certs:      certs,
		logger:     logger,
	}
	for _, r := range saved {
		m.res[r.ID] = r
		if err := m.startLocked(r); err != nil {
			m.logger.Warn("恢复资源失败", "id", r.ID, "name", r.Name, "error", err)
		}
	}
	return m, nil
}

// View 是资源在 API/UI 中的呈现：配置 + 运行状态 + 简要指标。
type View struct {
	*Resource
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// 简要监控（完整数据见 /api/resources/{id}/metrics）
	Requests int64 `json:"requests"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// List 返回全部资源的当前视图。
func (m *Manager) List() []View {
	m.mu.Lock()
	defer m.mu.Unlock()
	views := make([]View, 0, len(m.res))
	for _, r := range m.res {
		views = append(views, m.viewLocked(r))
	}
	return views
}

// Get 返回单个资源的视图。
func (m *Manager) Get(id string) (View, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.res[id]
	if !ok {
		return View{}, false
	}
	return m.viewLocked(r), true
}

// viewLocked 组装资源视图（调用方需持锁）。
func (m *Manager) viewLocked(r *Resource) View {
	v := View{
		Resource: r,
		Status:   m.statusLocked(r.ID),
		Error:    m.errMsg[r.ID],
	}
	if met := m.metrics[r.ID]; met != nil {
		met.mu.Lock()
		v.Requests, v.BytesIn, v.BytesOut = met.requests, met.bytesIn, met.bytesOut
		met.mu.Unlock()
	}
	return v
}

// Create 校验并创建资源，随即监听启动。端口冲突、证书无效等构造期
// 错误直接返回，资源不会落库。
func (m *Manager) Create(r *Resource) (View, error) {
	if err := r.validate(); err != nil {
		return View{}, err
	}
	id, err := newID()
	if err != nil {
		return View{}, err
	}
	r.ID = id

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.res {
		if e.Address == r.Address {
			return View{}, fmt.Errorf("地址 %s 已被资源 %q（%s）占用", r.Address, e.Name, e.ID)
		}
	}
	if err := m.startLocked(r); err != nil {
		return View{}, err
	}
	m.res[r.ID] = r
	if err := m.store.Save(m.snapshotLocked()); err != nil {
		// 持久化失败不影响运行中的实例，但要让调用方知道
		return View{}, fmt.Errorf("资源已启动但持久化失败: %w", err)
	}
	return View{Resource: r, Status: StatusRunning}, nil
}

// Start 启动已停止的资源。配置文件内容以启动时为准重新加载。
func (m *Manager) Start(id string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.res[id]
	if !ok {
		return View{}, fmt.Errorf("资源 %s 不存在", id)
	}
	if m.inst[id] != nil {
		return View{Resource: r, Status: StatusRunning}, nil
	}
	if err := m.startLocked(r); err != nil {
		return View{}, err
	}
	return View{Resource: r, Status: StatusRunning}, nil
}

// Update 编辑资源配置：替换 spec 后重建实例（运行中的资源先停止、
// 以新配置重启；已停止的只改配置不启动）。新配置构造失败时回滚：
// 恢复旧配置并尽量恢复旧实例，调用方拿到错误而资源不受损。
// ID 不可变；地址变更须未被其他资源占用。
func (m *Manager) Update(id string, r *Resource) (View, error) {
	r.ID = id
	if err := r.validate(); err != nil {
		return View{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.res[id]
	if !ok {
		return View{}, fmt.Errorf("资源 %s 不存在", id)
	}
	// 地址占用检查（与自身相同不算冲突）
	if r.Address != old.Address {
		for _, e := range m.res {
			if e.ID != id && e.Address == r.Address {
				return View{}, fmt.Errorf("地址 %s 已被资源 %q（%s）占用", r.Address, e.Name, e.ID)
			}
		}
	}

	wasRunning := m.inst[id] != nil
	if wasRunning {
		m.stopLocked(id)
	}
	m.res[id] = r

	if wasRunning {
		if err := m.startLocked(r); err != nil {
			// 回滚：恢复旧配置并尽力恢复旧实例
			m.res[id] = old
			delete(m.status, id)
			delete(m.errMsg, id)
			if err2 := m.startLocked(old); err2 != nil {
				m.status[id] = StatusError
				m.errMsg[id] = fmt.Sprintf("编辑失败且回滚重启失败: %v", err2)
				m.logger.Error("rollback start failed", "id", id, "name", old.Name, "error", err2)
			}
			return View{}, fmt.Errorf("新配置启动失败，已回滚: %w", err)
		}
	}

	if err := m.store.Save(m.snapshotLocked()); err != nil {
		return View{}, fmt.Errorf("配置已更新但持久化失败: %w", err)
	}
	m.logger.Info("resource updated", "id", id, "name", r.Name, "type", r.Type, "address", r.Address)
	return m.viewLocked(r), nil
}

// Stop 停止资源（断开监听与全部连接），保留配置。
func (m *Manager) Stop(id string) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.res[id]
	if !ok {
		return View{}, fmt.Errorf("资源 %s 不存在", id)
	}
	m.stopLocked(id)
	return View{Resource: r, Status: StatusStopped}, nil
}

// Delete 停止并删除资源，同时从持久化中移除。
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.res[id]; !ok {
		return fmt.Errorf("资源 %s 不存在", id)
	}
	m.stopLocked(id)
	delete(m.res, id)
	delete(m.status, id)
	delete(m.errMsg, id)
	return m.store.Save(m.snapshotLocked())
}

// startLocked 启动资源实例（调用方需持锁）。address 端口为 0 时
// 以实际绑定地址回写，便于调用方拿到随机端口。
func (m *Manager) startLocked(r *Resource) error {
	run, err := m.build(r)
	if err != nil {
		m.status[r.ID] = StatusError
		m.errMsg[r.ID] = err.Error()
		return err
	}

	ln, err := net.Listen("tcp", r.Address)
	if err != nil {
		m.status[r.ID] = StatusError
		m.errMsg[r.ID] = err.Error()
		return fmt.Errorf("监听 %s: %w", r.Address, err)
	}
	m.inst[r.ID] = &inst{ln: ln, stop: run.stop}
	delete(m.status, r.ID)
	delete(m.errMsg, r.ID)

	if r.Address != ln.Addr().String() && endsWithZeroPort(r.Address) {
		r.Address = ln.Addr().String()
	}
	m.logger.Info("resource started", "id", r.ID, "name", r.Name, "type", r.Type, "address", r.Address)

	go func() {
		serveErr := run.serve(ln)
		if serveErr != nil && serveErr != http.ErrServerClosed && !errors.Is(serveErr, net.ErrClosed) {
			m.mu.Lock()
			m.status[r.ID] = StatusError
			m.errMsg[r.ID] = serveErr.Error()
			delete(m.inst, r.ID)
			m.mu.Unlock()
			m.logger.Error("resource serve failed", "id", r.ID, "name", r.Name, "error", serveErr)
		}
	}()
	return nil
}

// stopLocked 停止实例（调用方需持锁）。stop 会中断监听与所有活动
// 连接（含 CONNECT 隧道），符合管理操作"立即生效"的预期。
func (m *Manager) stopLocked(id string) {
	if in := m.inst[id]; in != nil {
		_ = in.stop()
		delete(m.inst, id)
	}
	m.status[id] = StatusStopped
}

// statusLocked 返回资源状态（调用方需持锁）。
func (m *Manager) statusLocked(id string) string {
	if m.inst[id] != nil {
		return StatusRunning
	}
	if s := m.status[id]; s != "" {
		return s
	}
	return StatusStopped
}

// snapshotLocked 返回持久化用的资源快照（调用方需持锁）。
func (m *Manager) snapshotLocked() []*Resource {
	out := make([]*Resource, 0, len(m.res))
	for _, r := range m.res {
		out = append(out, r)
	}
	return out
}

// build 按资源类型构造可运行实例（serve/stop），证书按当前内容加载
// （Start 重启时生效新证书）。正向代理的处理器持有 UserStore 与
// metrics 的引用，用户增删与指标收集无需重建实例。
func (m *Manager) build(r *Resource) (runner, error) {
	switch r.Type {
	case TypeForward:
		return m.buildForward(r)
	case TypeReverse:
		return m.buildReverse(r)
	case TypeRelay:
		return m.buildRelay(r)
	case TypeSocks5:
		return m.buildSocks5(r)
	default:
		return runner{}, fmt.Errorf("未知资源类型 %q", r.Type)
	}
}

// httpRunner 把 http.Handler 包成 runner：serve 走 http.Server
// （有 TLS 配置时用 ServeTLS），stop 断开监听与全部连接。
// http1Only 为 true 时声明仅支持 HTTP/1.1（正向代理的 CONNECT 依赖
// Hijack，HTTP/2 的 ResponseWriter 不实现 http.Hijacker）；反向代理
// 不劫持连接，保留默认协议集（TLS 上可协商 h2）。
func httpRunner(handler http.Handler, tlsConf *tls.Config, http1Only bool) runner {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		TLSConfig:         tlsConf,
	}
	if http1Only {
		srv.Protocols = httpproxy.HTTP1OnlyProtocols()
	}
	return runner{
		serve: func(ln net.Listener) error {
			if tlsConf != nil {
				return srv.ServeTLS(ln, "", "")
			}
			return srv.Serve(ln)
		},
		stop: srv.Close,
	}
}

func (m *Manager) buildForward(r *Resource) (runner, error) {
	spec := r.Forward

	// 有任何认证配置（单用户或用户列表）时启用动态用户存储：
	// 单用户转为一条用户记录，Users 中的同名记录优先生效。
	var authenticator httpproxy.Authenticator
	store := httpproxy.NewUserStore()
	if spec.User != "" || len(spec.Users) > 0 {
		if spec.User != "" {
			if err := store.Add(spec.User, spec.Password); err != nil {
				return runner{}, err
			}
		}
		for i := range spec.Users {
			u := &spec.Users[i]
			if u.Password != "" {
				// 创建请求里带来的明文：计算摘要并清空明文（绝不持久化）
				if err := store.Add(u.User, u.Password); err != nil {
					return runner{}, err
				}
				u.Salt, u.Hash = storedDigest(store, u.User)
				u.Password = ""
			} else if u.Salt != "" && u.Hash != "" {
				store.AddStored(u.User, u.Salt, u.Hash)
			}
		}
		spec.Users = trimStored(spec.Users)
		authenticator = store
	}
	m.userStores[r.ID] = store

	upstream, err := netutil.UpstreamURL(spec.Upstream, spec.UpstreamUser, spec.UpstreamPassword)
	if err != nil {
		return runner{}, err
	}
	if upstream != nil && upstream.Scheme == "http" &&
		(spec.UpstreamCA != "" || spec.UpstreamCert != "" || spec.UpstreamKey != "") {
		return runner{}, fmt.Errorf("upstream_ca/upstream_cert/upstream_key 仅适用于 https 上游")
	}
	upstreamTLS, err := netutil.ClientTLSFromPEM(
		[]byte(spec.UpstreamCA), []byte(spec.UpstreamCert), []byte(spec.UpstreamKey))
	if err != nil {
		return runner{}, fmt.Errorf("配置上游 TLS: %w", err)
	}

	listenTLS, err := netutil.ServerTLSFromPEM([]byte(spec.Cert), []byte(spec.Key), []byte(spec.ClientCA))
	if err != nil {
		return runner{}, err
	}

	proxy, err := httpproxy.New(httpproxy.Options{
		Authenticator: authenticator,
		Upstream:      upstream,
		UpstreamTLS:   upstreamTLS,
		Metrics:       m.metricsOf(r.ID),
	})
	if err != nil {
		return runner{}, err
	}
	return httpRunner(proxy, listenTLS, true), nil
}

// storedDigest 从 store 取回某用户的 salt/hash（Add 之后立即调用，
// 保证记录存在）。
func storedDigest(store *httpproxy.UserStore, user string) (string, string) {
	salt, hash, _ := store.StoredDigest(user)
	return salt, hash
}

// trimStored 过滤掉既无明文也无摘要的无效用户记录。
func trimStored(users []StoredUser) []StoredUser {
	out := users[:0]
	for _, u := range users {
		if u.User != "" && (u.Salt != "" && u.Hash != "") {
			out = append(out, u)
		}
	}
	return out
}

// metricsOf 返回（或懒创建）资源的指标聚合器。
func (m *Manager) metricsOf(id string) *resourceMetrics {
	if met, ok := m.metrics[id]; ok {
		return met
	}
	met := newResourceMetrics()
	m.metrics[id] = met
	return met
}

func (m *Manager) buildReverse(r *Resource) (runner, error) {
	spec := r.Reverse

	var opts []reverseproxy.Option
	if spec.BackendCA != "" || spec.BackendCert != "" || spec.BackendKey != "" {
		opts = append(opts, reverseproxy.WithBackendTLS(reverseproxy.BackendTLSConfig{
			CAPEM:   []byte(spec.BackendCA),
			CertPEM: []byte(spec.BackendCert),
			KeyPEM:  []byte(spec.BackendKey),
		}))
	}

	listenTLS, err := netutil.ServerTLSFromPEM([]byte(spec.Cert), []byte(spec.Key), []byte(spec.ClientCA))
	if err != nil {
		return runner{}, err
	}

	handler, err := reverseproxy.New(spec.Backends, opts...)
	if err != nil {
		return runner{}, err
	}
	// 反向代理没有 httpproxy 的埋点，用中间件统计请求数/状态码/
	// 响应字节数，与正向资源喂进同一个聚合器
	return httpRunner(metricsMiddleware(handler, m.metricsOf(r.ID)), listenTLS, false), nil
}

// buildRelay 构造 TCP 中继资源：监听端与每个上游的 TLS 分别构建
// （PEM 内容），监听端 TLS 的包装由 relay.Serve 自行完成。
func (m *Manager) buildRelay(r *Resource) (runner, error) {
	spec := r.Relay

	listenTLS, err := netutil.ServerTLSFromPEM([]byte(spec.Cert), []byte(spec.Key), []byte(spec.ClientCA))
	if err != nil {
		return runner{}, err
	}

	dialTimeout := 10 * time.Second
	if spec.DialTimeout != "" {
		if dialTimeout, err = time.ParseDuration(spec.DialTimeout); err != nil {
			return runner{}, fmt.Errorf("dial_timeout: %w", err)
		}
	}
	idleTimeout := 2 * time.Minute
	if spec.IdleTimeout != "" {
		if idleTimeout, err = time.ParseDuration(spec.IdleTimeout); err != nil {
			return runner{}, fmt.Errorf("idle_timeout: %w", err)
		}
	}

	ups := make([]relay.Upstream, 0, len(spec.Upstreams))
	for _, u := range spec.Upstreams {
		up := relay.Upstream{Address: u.Address, Weight: u.Weight}
		if u.CA != "" || u.Cert != "" || u.Key != "" {
			up.TLS, err = netutil.ClientTLSFromPEM([]byte(u.CA), []byte(u.Cert), []byte(u.Key))
			if err != nil {
				return runner{}, fmt.Errorf("配置上游 %s TLS: %w", u.Address, err)
			}
		}
		ups = append(ups, up)
	}

	rel, err := relay.NewWithOptions(relay.Options{
		Listen:      r.Address,
		ListenTLS:   listenTLS,
		Upstreams:   ups,
		DialTimeout: dialTimeout,
		IdleTimeout: idleTimeout,
		Logger:      m.logger,
	})
	if err != nil {
		return runner{}, err
	}
	return runner{serve: rel.Serve, stop: rel.Close}, nil
}

// buildSocks5 构造 SOCKS5 代理资源：认证为 RFC 1929 单用户，监听端
// TLS 在 serve 里包装。
func (m *Manager) buildSocks5(r *Resource) (runner, error) {
	spec := r.Socks5

	var authenticator socks5.Authenticator
	if spec.User != "" {
		authenticator = &socks5.Credentials{Username: spec.User, Password: spec.Password}
	}

	listenTLS, err := netutil.ServerTLSFromPEM([]byte(spec.Cert), []byte(spec.Key), []byte(spec.ClientCA))
	if err != nil {
		return runner{}, err
	}

	proxy, err := socks5.New(socks5.Options{
		Authenticator: authenticator,
		Logger:        m.logger,
	})
	if err != nil {
		return runner{}, err
	}
	return runner{
		serve: func(ln net.Listener) error {
			if listenTLS != nil {
				ln = tls.NewListener(ln, listenTLS)
			}
			return proxy.Serve(ln)
		},
		stop: proxy.Close,
	}, nil
}

// metricsMiddleware 把 reverseproxy 的请求喂给 resourceMetrics
// （请求计数、状态码、响应字节数；请求体字节数经计数包装读取）。
func metricsMiddleware(next http.Handler, met *resourceMetrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		met.Request("", r.Method, r.URL.Path)
		body := &countingReadCloser{r: r.Body}
		r.Body = body
		cw := &countingWriter{ResponseWriter: w}
		next.ServeHTTP(cw, r)
		met.BytesIn(body.n)
		met.BytesOut(cw.n)
		met.Response(cw.status)
	})
}

// countingReadCloser 统计请求体读出的字节数。
type countingReadCloser struct {
	r io.ReadCloser
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReadCloser) Close() error { return c.r.Close() }

// countingWriter 统计写出的字节数并记录状态码。
type countingWriter struct {
	http.ResponseWriter
	n      int64
	status int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *countingWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Metrics 返回资源的监控快照。
func (m *Manager) Metrics(id string) (MetricsView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.res[id]; !ok {
		return MetricsView{}, fmt.Errorf("资源 %s 不存在", id)
	}
	return m.metricsOf(id).view(), nil
}

// Users 列出正向代理资源的认证用户。
func (m *Manager) Users(id string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.res[id]
	if !ok {
		return nil, fmt.Errorf("资源 %s 不存在", id)
	}
	if r.Type != TypeForward {
		return nil, fmt.Errorf("只有 forward 资源支持用户管理")
	}
	return m.forwardUsersLocked(r), nil
}

// AddUser 给正向代理资源添加/更新用户。资源运行中且已启用认证时
// 立即生效（无需重建实例）；原资源未启用认证时，重启实例以挂上认证器。
func (m *Manager) AddUser(id, user, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.res[id]
	if !ok {
		return fmt.Errorf("资源 %s 不存在", id)
	}
	if r.Type != TypeForward {
		return fmt.Errorf("只有 forward 资源支持用户管理")
	}
	if user == "" || password == "" {
		return fmt.Errorf("user 与 password 不能为空")
	}

	authEnabled := r.Forward.User != "" || len(r.Forward.Users) > 0
	store := m.userStores[id]
	if store == nil {
		store = httpproxy.NewUserStore()
		m.userStores[id] = store
	}
	if err := store.Add(user, password); err != nil {
		return err
	}
	upsertStoredUser(r.Forward, user, store)

	if !authEnabled && m.inst[id] != nil {
		// 实例构建时未启用认证，重启以挂上认证器（断开现有连接）
		m.stopLocked(id)
		if err := m.startLocked(r); err != nil {
			return fmt.Errorf("启用认证需要重启实例，重启失败: %w", err)
		}
	}
	m.logger.Info("user added", "id", r.ID, "resource", r.Name, "user", user)
	return m.store.Save(m.snapshotLocked())
}

// RemoveUser 删除正向代理资源的用户，运行中即时生效。
func (m *Manager) RemoveUser(id, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.res[id]
	if !ok {
		return fmt.Errorf("资源 %s 不存在", id)
	}
	if r.Type != TypeForward {
		return fmt.Errorf("只有 forward 资源支持用户管理")
	}

	removed := false
	if store := m.userStores[id]; store != nil {
		removed = store.Remove(user)
	}
	if r.Forward.User == user {
		r.Forward.User, r.Forward.Password = "", ""
		removed = true
	}
	filtered := r.Forward.Users[:0]
	for _, u := range r.Forward.Users {
		if u.User != user {
			filtered = append(filtered, u)
		} else {
			removed = true
		}
	}
	r.Forward.Users = filtered
	if !removed {
		return fmt.Errorf("用户 %q 不存在", user)
	}
	m.logger.Info("user removed", "id", r.ID, "resource", r.Name, "user", user)
	return m.store.Save(m.snapshotLocked())
}

// forwardUsersLocked 汇总资源的全部用户名（单用户 + users 列表）。
// 始终返回非 nil 切片，避免 JSON 序列化为 null。
func (m *Manager) forwardUsersLocked(r *Resource) []string {
	seen := map[string]bool{}
	names := []string{}
	if r.Forward.User != "" {
		names = append(names, r.Forward.User)
		seen[r.Forward.User] = true
	}
	for _, u := range r.Forward.Users {
		if u.User != "" && !seen[u.User] {
			names = append(names, u.User)
			seen[u.User] = true
		}
	}
	return names
}

// upsertStoredUser 把用户以 salt/hash 形式并入 spec.Users（同名覆盖）。
func upsertStoredUser(spec *ForwardSpec, user string, store *httpproxy.UserStore) {
	salt, hash := storedDigest(store, user)
	updated := false
	for i, u := range spec.Users {
		if u.User == user {
			spec.Users[i].Salt, spec.Users[i].Hash = salt, hash
			spec.Users[i].Password = ""
			updated = true
			break
		}
	}
	if !updated {
		spec.Users = append(spec.Users, StoredUser{User: user, Salt: salt, Hash: hash})
	}
	// 单用户形式与新记录重名时移除，避免两处凭证打架
	if spec.User == user {
		spec.User, spec.Password = "", ""
	}
}

// newID 生成 8 字节随机十六进制资源 ID。
func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成资源 ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// endsWithZeroPort 判断地址是否以 :0 结尾（请求随机端口）。
func endsWithZeroPort(addr string) bool {
	return len(addr) >= 2 && addr[len(addr)-2:] == ":0"
}

// recordCA 记录并持久化生成的一套证书中的 CA（含私钥，可继续签发）。
// 持久化失败只记日志，不影响证书生成结果返回调用方。
func (m *Manager) recordCA(ca *certgen.CA, algorithm, cn string) {
	if cn == "" {
		cn = "open-proxy-ca"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := newID()
	if err != nil {
		m.logger.Warn("生成证书记录 ID 失败", "error", err)
		return
	}
	if _, err := m.certs.createCA(id, ca, algorithm, cn); err != nil {
		m.logger.Warn("CA 持久化失败", "error", err)
	}
}

// recordCert 记录并持久化一张签发出的证书（与返回调用方的是同一张）。
// caPEM 用于关联已存储的 CA 记录。
func (m *Manager) recordCert(caPEM string, certPEM, keyPEM []byte, opts certgen.CertOptions) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := newID()
	if err != nil {
		m.logger.Warn("生成证书记录 ID 失败", "error", err)
		return
	}
	if _, err := m.certs.saveCert(id, caPEM, certPEM, keyPEM, opts); err != nil {
		m.logger.Warn("证书持久化失败", "error", err)
	}
}

// ListCAs 返回已保存的 CA 记录（按创建时间从新到旧）。
func (m *Manager) ListCAs() []*CARecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certs.listCAs()
}

// ListCerts 返回已保存的证书记录（按创建时间从新到旧）。
func (m *Manager) ListCerts() []*CertRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certs.listCerts()
}

// DeleteCA 删除已保存的 CA 记录（由它签发的证书记录保留，可溯源 CA 名称）。
func (m *Manager) DeleteCA(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.certs.deleteCA(id) {
		return fmt.Errorf("CA 记录 %s 不存在", id)
	}
	return m.certs.saveLocked()
}

// DeleteCert 删除已保存的证书记录。
func (m *Manager) DeleteCert(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.certs.deleteCert(id) {
		return fmt.Errorf("证书记录 %s 不存在", id)
	}
	return m.certs.saveLocked()
}

// CreateCA 创建根 CA 并持久化（不自动签发任何叶子证书）。
// 返回完整的 CA 记录（含证书与私钥 PEM）。
func (m *Manager) CreateCA(cn string, org []string, days int, algorithm string, curve string, rsaBits int) (*CARecord, error) {
	algo, err := certgen.ParseAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	c, err := certgen.ParseCurve(curve)
	if err != nil {
		return nil, err
	}
	if cn == "" {
		cn = "open-proxy-ca"
	}
	ca, err := certgen.NewCA(certgen.CAOptions{
		CommonName:   cn,
		Organization: org,
		Days:         days,
		Algorithm:    algo,
		Curve:        c,
		RSABits:      rsaBits,
	})
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return m.certs.createCA(id, ca, string(algo), cn)
}

// IssueFromCA 用已保存的 CA（按 ID）签发一张叶子证书并持久化。
// 返回签发出的证书与私钥 PEM。
func (m *Manager) IssueFromCA(caID string, opts certgen.CertOptions) (certPEM, keyPEM []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ca, ok := m.certs.cas[caID]
	if !ok {
		return nil, nil, fmt.Errorf("CA 记录 %s 不存在", caID)
	}
	loaded, err := certgen.LoadCA([]byte(ca.CertPEM), []byte(ca.KeyPEM))
	if err != nil {
		return nil, nil, fmt.Errorf("加载 CA: %w", err)
	}
	certPEM, keyPEM, err = loaded.Issue(opts)
	if err != nil {
		return nil, nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, nil, err
	}
	if _, err := m.certs.saveCert(id, ca.CertPEM, certPEM, keyPEM, opts); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// LookupCA 按内容匹配已保存的 CA（粘贴 PEM 签发时用于关联）。
func (m *Manager) LookupCA(caPEM string) (*CARecord, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ca := range m.certs.cas {
		if ca.CertPEM == caPEM {
			return ca, true
		}
	}
	return nil, false
}

// ImportCA 导入已有 CA（证书 + 私钥 PEM）并持久化，之后可直接从它签发。
// remark 为用户备注（可为空）。
func (m *Manager) ImportCA(certPEM, keyPEM, remark string) (*CARecord, error) {
	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("证书与私钥 PEM 不能为空")
	}
	if err := checkRemark(remark); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return m.certs.importCA(id, certPEM, keyPEM, remark)
}

// ImportCert 导入一张已签发的证书（证书 + 私钥 PEM）并持久化。
// caID 可选，给出时关联已存储的 CA 记录；remark 为用户备注（可为空）。
func (m *Manager) ImportCert(certPEM, keyPEM, caID, remark string) (*CertRecord, error) {
	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("证书与私钥 PEM 不能为空")
	}
	if err := checkRemark(remark); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return m.certs.importCert(id, certPEM, keyPEM, caID, remark)
}

// maxRemarkLen 备注长度上限（防止把大段文本塞进记录）。
const maxRemarkLen = 256

// checkRemark 校验备注长度。
func checkRemark(remark string) error {
	if len(remark) > maxRemarkLen {
		return fmt.Errorf("备注最长 %d 字符", maxRemarkLen)
	}
	return nil
}

// SetCARemark / SetCertRemark 更新已保存记录的备注
// （区分同域名/同 CN 的多张证书），并持久化。
func (m *Manager) SetCARemark(id, remark string) (*CARecord, error) {
	if err := checkRemark(remark); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certs.setCARemark(id, remark)
}

func (m *Manager) SetCertRemark(id, remark string) (*CertRecord, error) {
	if err := checkRemark(remark); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certs.setCertRemark(id, remark)
}

// ExportCertPFX 把已保存的证书记录导出为 PKCS#12（浏览器导入用），
// 返回 DER 字节。password 为导入口令。
func (m *Manager) ExportCertPFX(id, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("导入口令不能为空")
	}
	m.mu.Lock()
	rec, ok := m.certs.certs[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("证书记录 %s 不存在", id)
	}
	return certgen.MarshalPKCS12([]byte(rec.CertPEM), []byte(rec.KeyPEM), nil, password)
}
