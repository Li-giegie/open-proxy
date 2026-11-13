// Package admin 是 open-proxy 的管理中心：以 Web UI + REST API 的方式
// 创建和管理代理资源（forward / reverse）。资源以进程内 http.Server
// 实例运行，配置持久化到 JSON 文件，重启后自动恢复。
//
// 这是一个独立模块：只依赖 internal/httpproxy、internal/reverseproxy
// 和 internal/proxycfg，不反向依赖 cmd 层。
package admin

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Li-giegie/open-proxy/internal/httpproxy"
	"github.com/Li-giegie/open-proxy/internal/proxycfg"
	"github.com/Li-giegie/open-proxy/internal/reverseproxy"
)

// 资源运行状态。
const (
	StatusRunning = "running"
	StatusStopped = "stopped"
	StatusError   = "error"
)

// inst 是一个正在运行的代理实例。
type inst struct {
	srv *http.Server
	ln  net.Listener
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
	logger  *slog.Logger
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
	m := &Manager{
		store:      store,
		res:        make(map[string]*Resource, len(saved)),
		inst:       map[string]*inst{},
		status:     map[string]string{},
		errMsg:     map[string]string{},
		userStores: map[string]*httpproxy.UserStore{},
		metrics:    map[string]*resourceMetrics{},
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
	handler, tlsConf, err := m.build(r)
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

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		TLSConfig:         tlsConf,
	}
	// 正向代理的 CONNECT 隧道依赖 Hijack 劫持连接，而 HTTP/2 的
	// ResponseWriter 不实现 http.Hijacker，隧道无法建立。显式声明
	// 只支持 HTTP/1.1，TLS ALPN 因此只协商 http/1.1。
	// 反向代理不需要劫持连接，保留 HTTP/2。
	if r.Type == TypeForward {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		srv.Protocols = protocols
	}
	m.inst[r.ID] = &inst{srv: srv, ln: ln}
	delete(m.status, r.ID)
	delete(m.errMsg, r.ID)

	if r.Address != ln.Addr().String() && endsWithZeroPort(r.Address) {
		r.Address = ln.Addr().String()
	}
	m.logger.Info("resource started", "id", r.ID, "name", r.Name, "type", r.Type, "address", r.Address)

	go func() {
		var serveErr error
		if tlsConf != nil {
			serveErr = srv.ServeTLS(ln, "", "")
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
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

// stopLocked 停止实例（调用方需持锁）。Close 会中断监听与所有活动
// 连接（含 CONNECT 隧道），符合管理操作"立即生效"的预期。
func (m *Manager) stopLocked(id string) {
	if in := m.inst[id]; in != nil {
		_ = in.srv.Close()
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

// build 按资源类型构造处理器与监听端 TLS 配置，证书文件按当前磁盘
// 内容加载（Start 重启时生效新证书）。正向代理的处理器持有 UserStore
// 与 metrics 的引用，用户增删与指标收集无需重建实例。
func (m *Manager) build(r *Resource) (http.Handler, *tls.Config, error) {
	switch r.Type {
	case TypeForward:
		return m.buildForward(r)
	case TypeReverse:
		return m.buildReverse(r)
	default:
		return nil, nil, fmt.Errorf("未知资源类型 %q", r.Type)
	}
}

func (m *Manager) buildForward(r *Resource) (http.Handler, *tls.Config, error) {
	spec := r.Forward

	// 有任何认证配置（单用户或用户列表）时启用动态用户存储：
	// 单用户转为一条用户记录，Users 中的同名记录优先生效。
	var authenticator httpproxy.Authenticator
	store := httpproxy.NewUserStore()
	if spec.User != "" || len(spec.Users) > 0 {
		if spec.User != "" {
			if err := store.Add(spec.User, spec.Password); err != nil {
				return nil, nil, err
			}
		}
		for i := range spec.Users {
			u := &spec.Users[i]
			if u.Password != "" {
				// 创建请求里带来的明文：计算摘要并清空明文（绝不持久化）
				if err := store.Add(u.User, u.Password); err != nil {
					return nil, nil, err
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

	upstream, err := proxycfg.UpstreamURL(spec.Upstream, spec.UpstreamUser, spec.UpstreamPassword)
	if err != nil {
		return nil, nil, err
	}
	if upstream != nil && upstream.Scheme == "http" &&
		(spec.UpstreamCA != "" || spec.UpstreamCert != "" || spec.UpstreamKey != "") {
		return nil, nil, fmt.Errorf("upstream_ca/upstream_cert/upstream_key 仅适用于 https 上游")
	}
	upstreamTLS, err := proxycfg.ClientTLSFromPEM(
		[]byte(spec.UpstreamCA), []byte(spec.UpstreamCert), []byte(spec.UpstreamKey))
	if err != nil {
		return nil, nil, fmt.Errorf("配置上游 TLS: %w", err)
	}

	listenTLS, err := proxycfg.ServerTLSFromPEM([]byte(spec.Cert), []byte(spec.Key), []byte(spec.ClientCA))
	if err != nil {
		return nil, nil, err
	}

	proxy, err := httpproxy.New(httpproxy.Options{
		Authenticator: authenticator,
		Upstream:      upstream,
		UpstreamTLS:   upstreamTLS,
		Metrics:       m.metricsOf(r.ID),
	})
	if err != nil {
		return nil, nil, err
	}
	return proxy, listenTLS, nil
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

func (m *Manager) buildReverse(r *Resource) (http.Handler, *tls.Config, error) {
	spec := r.Reverse

	var opts []reverseproxy.Option
	if spec.BackendCA != "" || spec.BackendCert != "" || spec.BackendKey != "" {
		opts = append(opts, reverseproxy.WithBackendTLS(reverseproxy.BackendTLSConfig{
			CAPEM:   []byte(spec.BackendCA),
			CertPEM: []byte(spec.BackendCert),
			KeyPEM:  []byte(spec.BackendKey),
		}))
	}

	listenTLS, err := proxycfg.ServerTLSFromPEM([]byte(spec.Cert), []byte(spec.Key), []byte(spec.ClientCA))
	if err != nil {
		return nil, nil, err
	}

	handler, err := reverseproxy.New(spec.Backends, opts...)
	if err != nil {
		return nil, nil, err
	}
	// 反向代理没有 httpproxy 的埋点，用中间件统计请求数/状态码/
	// 响应字节数，与正向资源喂进同一个聚合器
	return metricsMiddleware(handler, m.metricsOf(r.ID)), listenTLS, nil
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
