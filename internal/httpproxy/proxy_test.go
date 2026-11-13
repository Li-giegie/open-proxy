package httpproxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// proxyClient 返回一个把请求经由 proxyURL 转发的 HTTP 客户端。
// 代理 URL 带 userinfo 时，Transport 会自动附带 Proxy-Authorization。
func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return u, nil },
		},
	}
}

func TestForward(t *testing.T) {
	var (
		gotPath   string
		gotMethod string
		gotHeader http.Header
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotHeader = r.Header.Clone()
		if r.Header.Get("Connection") != "" || r.Header.Get("Proxy-Connection") != "" ||
			r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("upstream received hop-by-hop header: %v", r.Header)
		}
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("upstream missing X-Forwarded-For")
		}
		w.Header().Set("X-Custom", "custom-value")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("upstream body"))
	}))
	defer upstream.Close()

	proxy, err := New(Options{Authenticator: &Credentials{Username: "u", Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	client := proxyClient(t, strings.Replace(proxySrv.URL, "http://", "http://u:p@", 1))
	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/path", strings.NewReader("req body"))
	if err != nil {
		t.Fatal(err)
	}
	// 客户端可能带上的逐跳头，代理必须剔除后再转发
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("forward request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
	if resp.Header.Get("X-Custom") != "custom-value" {
		t.Errorf("X-Custom = %q, upstream header not forwarded", resp.Header.Get("X-Custom"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "upstream body" {
		t.Errorf("body = %q", body)
	}
	if gotMethod != http.MethodPost || gotPath != "/path" {
		t.Errorf("upstream saw %s %s", gotMethod, gotPath)
	}
	if len(gotHeader) == 0 {
		t.Fatal("upstream received no headers")
	}
}

func TestRedirectPassThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer upstream.Close()

	proxy, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL)
	// 客户端不自动跟随重定向，验证 302 由代理原样透传
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (redirect must pass through)", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/other" {
		t.Errorf("Location = %q, want /other", resp.Header.Get("Location"))
	}
}

func TestAuthRequired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	proxy, err := New(Options{Authenticator: &Credentials{Username: "u", Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	// 不带凭据
	resp, err := proxyClient(t, proxySrv.URL).Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Errorf("missing Proxy-Authenticate challenge")
	}
}

// tokenAuth 是自定义认证器示例：按固定 Token 校验。
type tokenAuth struct{ token string }

func (a *tokenAuth) Authenticate(req *http.Request) bool {
	return req.Header.Get("Proxy-Authorization") == "Bearer "+a.token
}

func (a *tokenAuth) Challenge() string { return `Bearer realm="open-proxy"` }

// TestCustomAuthenticator 验证认证方式可通过接口替换。
func TestCustomAuthenticator(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy, err := New(Options{Authenticator: &tokenAuth{token: "secret-token"}})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	// 错误 Token
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer wrong")
	resp, err := proxyClient(t, proxySrv.URL).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("wrong token: status = %d, want 407", resp.StatusCode)
	}

	// 正确 Token
	req, _ = http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer secret-token")
	resp, err = proxyClient(t, proxySrv.URL).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("right token: status = %d, want 200", resp.StatusCode)
	}
}

func TestConnectTunnel(t *testing.T) {
	// echo 上游
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	proxy, err := New(Options{Authenticator: &Credentials{Username: "u", Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CONNECT 与载荷一起发送：载荷会落在代理的 bufio 缓冲里，
	// 验证 drainBuffered 没有丢数据
	payload := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\nearly-data",
		echo.Addr(), echo.Addr(), auth)
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	// 先读到握手前抢先发送的 early-data 的回显，再验证后续数据
	buf := make([]byte, len("early-data"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read early data echo: %v", err)
	}
	if string(buf) != "early-data" {
		t.Errorf("early data = %q, want %q", buf, "early-data")
	}

	if _, err := conn.Write([]byte("late-data")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("late-data"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read late data echo: %v", err)
	}
	if string(buf) != "late-data" {
		t.Errorf("late data = %q", buf)
	}
}

func TestTunnelIdleTimeout(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				c.Close()
			}()
		}
	}()

	proxy, err := New(Options{TunnelIdleTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 不发任何数据，隧道应在 idleTimeout 后被代理断开
	if _, err := br.ReadByte(); err == nil {
		t.Errorf("tunnel still open after idle timeout")
	}
}

// startEcho 启动一个原样回显的 TCP 服务，用于测试 CONNECT 隧道。
func startEcho(t *testing.T) net.Addr {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return echo.Addr()
}

// mustUpstreamURL 解析上游代理地址（带可选 userinfo）。
func mustUpstreamURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestChainForward 验证代理链上的普通 HTTP 转发：客户端 → 本地代理 →
// 上游代理 → 目标，目标能收到请求且 XFF 被追加。
func TestChainForward(t *testing.T) {
	var gotPath string
	var gotXFF string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.Write([]byte("chain-ok"))
	}))
	defer target.Close()

	up, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	upSrv := httptest.NewServer(up)
	defer upSrv.Close()

	local, err := New(Options{Upstream: mustUpstreamURL(t, upSrv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	localSrv := httptest.NewServer(local)
	defer localSrv.Close()

	resp, err := proxyClient(t, localSrv.URL).Get(target.URL + "/chain")
	if err != nil {
		t.Fatalf("chain request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "chain-ok" {
		t.Errorf("body = %q, want %q", body, "chain-ok")
	}
	if gotPath != "/chain" {
		t.Errorf("target path = %q, want /chain", gotPath)
	}
	if gotXFF == "" {
		t.Errorf("target missing X-Forwarded-For")
	}
}

// TestChainConnect 验证代理链上的 CONNECT：本地代理向上游发 CONNECT
// 建隧道，客户端的 early-data 与后续数据都经两层隧道到 echo 再回显。
func TestChainConnect(t *testing.T) {
	echoAddr := startEcho(t)

	up, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	upSrv := httptest.NewServer(up)
	defer upSrv.Close()

	local, err := New(Options{Upstream: mustUpstreamURL(t, upSrv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	localSrv := httptest.NewServer(local)
	defer localSrv.Close()
	localAddr := strings.TrimPrefix(localSrv.URL, "http://")

	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nearly-data",
		echoAddr.String(), echoAddr.String())
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	buf := make([]byte, len("early-data"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read early data echo: %v", err)
	}
	if string(buf) != "early-data" {
		t.Errorf("early data = %q, want %q", buf, "early-data")
	}

	if _, err := conn.Write([]byte("late-data")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("late-data"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read late data echo: %v", err)
	}
	if string(buf) != "late-data" {
		t.Errorf("late data = %q, want %q", buf, "late-data")
	}
}

// TestChainUpstreamAuth 验证上游代理的 Basic 认证：本地代理经 Upstream
// URL 的 userinfo 携带凭证；不带凭证时应失败。
func TestChainUpstreamAuth(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("auth-ok"))
	}))
	defer target.Close()

	up, err := New(Options{Authenticator: &Credentials{Username: "u", Password: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	upSrv := httptest.NewServer(up)
	defer upSrv.Close()
	upAddr := strings.TrimPrefix(upSrv.URL, "http://")

	// 带凭证：成功
	local, err := New(Options{Upstream: mustUpstreamURL(t, "http://u:p@"+upAddr)})
	if err != nil {
		t.Fatal(err)
	}
	localSrv := httptest.NewServer(local)
	defer localSrv.Close()
	resp, err := proxyClient(t, localSrv.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("auth chain request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "auth-ok" {
		t.Errorf("body = %q, want %q", body, "auth-ok")
	}

	// 不带凭证：上游 407 → 拨号失败 → 502
	local2, err := New(Options{Upstream: mustUpstreamURL(t, "http://"+upAddr)})
	if err != nil {
		t.Fatal(err)
	}
	localSrv2 := httptest.NewServer(local2)
	defer localSrv2.Close()
	resp, err = proxyClient(t, localSrv2.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("no-auth chain request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("no auth: status = %d, want 502", resp.StatusCode)
	}
}

// TestChainConnectRejected 验证上游拒绝 CONNECT（非 2xx）时本地代理
// 向客户端返回 502。
func TestChainConnectRejected(t *testing.T) {
	// 伪装上游：对 CONNECT 一律 403
	rejector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer rejector.Close()

	local, err := New(Options{Upstream: mustUpstreamURL(t, rejector.URL)})
	if err != nil {
		t.Fatal(err)
	}
	localSrv := httptest.NewServer(local)
	defer localSrv.Close()
	localAddr := strings.TrimPrefix(localSrv.URL, "http://")

	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502（上游拒绝应透传为 502）", resp.StatusCode)
	}
}

// TestNewUpstreamValidation 验证非法 Upstream 在构造期报错。
func TestNewUpstreamValidation(t *testing.T) {
	u := &url.URL{Scheme: "socks5", Host: "127.0.0.1:1080"}
	if _, err := New(Options{Upstream: u}); err == nil {
		t.Errorf("socks5 upstream: want error")
	}
}

// TestUserStore 验证动态用户存储：增删即时生效、密码摘要持久化往返、
// 恒定拒绝错误密码。
func TestUserStore(t *testing.T) {
	s := NewUserStore()

	req := func(user, pass string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		r.Header.Set("Proxy-Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		return r
	}

	// 空存储：拒绝
	if s.Authenticate(req("u", "p")) {
		t.Fatal("empty store should reject")
	}

	// 添加后：正确密码通过，错误密码拒绝
	if err := s.Add("alice", "pw1"); err != nil {
		t.Fatal(err)
	}
	if !s.Authenticate(req("alice", "pw1")) {
		t.Fatal("alice/pw1 should pass")
	}
	if s.Authenticate(req("alice", "wrong")) {
		t.Fatal("wrong password should reject")
	}
	if s.Authenticate(req("bob", "pw1")) {
		t.Fatal("unknown user should reject")
	}
	if s.User(req("alice", "pw1")) != "alice" {
		t.Errorf("User() = %q, want alice", s.User(req("alice", "pw1")))
	}

	// 覆盖密码
	_ = s.Add("alice", "pw2")
	if s.Authenticate(req("alice", "pw1")) {
		t.Fatal("old password should reject after update")
	}
	if !s.Authenticate(req("alice", "pw2")) {
		t.Fatal("new password should pass")
	}

	// 持久化摘要往返
	salt, hash, ok := s.StoredDigest("alice")
	if !ok || salt == "" || hash == "" {
		t.Fatalf("StoredDigest = %q %q %v", salt, hash, ok)
	}
	restored := NewUserStore()
	restored.AddStored("alice", salt, hash)
	if !restored.Authenticate(req("alice", "pw2")) {
		t.Fatal("restored digest should authenticate")
	}

	// 删除后拒绝
	s.Remove("alice")
	if s.Authenticate(req("alice", "pw2")) {
		t.Fatal("removed user should reject")
	}

	// 用户名校验
	if err := s.Add("", "x"); err == nil {
		t.Error("empty username: want error")
	}
}

// fakeMetrics 是测试用指标收集器（并发安全：字节计数来自隧道两侧的
// 独立 goroutine）。
type fakeMetrics struct {
	mu        sync.Mutex
	requests  []string // "user|method|url"
	responses []int
	in, out   int64
}

func (f *fakeMetrics) Request(user, method, url string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, user+"|"+method+"|"+url)
}
func (f *fakeMetrics) Response(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses = append(f.responses, status)
}
func (f *fakeMetrics) BytesIn(n int64) {
	f.mu.Lock()
	f.in += n
	f.mu.Unlock()
}
func (f *fakeMetrics) BytesOut(n int64) {
	f.mu.Lock()
	f.out += n
	f.mu.Unlock()
}

// TestMetricsForward 验证普通转发的指标埋点：请求（含用户名）、
// 状态码、双向字节数。
func TestMetricsForward(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0123456789"))
	}))
	defer target.Close()

	met := &fakeMetrics{}
	proxy, err := New(Options{Authenticator: &Credentials{Username: "u", Password: "p"}, Metrics: met})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	client := proxyClient(t, strings.Replace(proxySrv.URL, "http://", "http://u:p@", 1))
	resp, err := client.Post(target.URL+"/path", "text/plain", strings.NewReader("req-body"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if len(met.requests) != 1 || met.requests[0] != "u|POST|"+target.URL+"/path" {
		t.Errorf("requests = %v, want [u|POST|%s/path]", met.requests, target.URL)
	}
	if len(met.responses) != 1 || met.responses[0] != http.StatusOK {
		t.Errorf("responses = %v, want [200]", met.responses)
	}
	if met.in != int64(len("req-body")) {
		t.Errorf("BytesIn = %d, want %d", met.in, len("req-body"))
	}
	if met.out < int64(len("0123456789")) {
		t.Errorf("BytesOut = %d, want >= %d", met.out, len("0123456789"))
	}
}

// TestMetricsConnect 验证 CONNECT 隧道的指标埋点：请求、200 状态、
// 双向字节数（含 early-data）。
func TestMetricsConnect(t *testing.T) {
	echoAddr := startEcho(t)

	met := &fakeMetrics{}
	proxy, err := New(Options{Metrics: met})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nearly", echoAddr.String(), echoAddr.String())
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	buf := make([]byte, len("early"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if _, err := conn.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("late"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	conn.Close()

	// 等隧道两端结束，指标落账
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if met.in >= int64(len("early")+len("late")) && met.out >= int64(len("early")+len("late")) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(met.requests) != 1 || met.requests[0] != "|CONNECT|"+echoAddr.String() {
		t.Errorf("requests = %v, want [|CONNECT|%s]", met.requests, echoAddr.String())
	}
	if len(met.responses) != 1 || met.responses[0] != http.StatusOK {
		t.Errorf("responses = %v, want [200]", met.responses)
	}
	if met.in != int64(len("early")+len("late")) {
		t.Errorf("BytesIn = %d, want %d", met.in, len("early")+len("late"))
	}
	if met.out != int64(len("early")+len("late")) {
		t.Errorf("BytesOut = %d, want %d", met.out, len("early")+len("late"))
	}
}

// TestMetricsConnectLive 验证隧道字节数在连接保持打开期间就已入账
// （而非断开后才结算）。
func TestMetricsConnectLive(t *testing.T) {
	echoAddr := startEcho(t)

	met := &fakeMetrics{}
	proxy, err := New(Options{Metrics: met})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr.String(), echoAddr.String())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}

	// 收发一轮数据，但不关闭连接
	if _, err := conn.Write([]byte("live-bytes")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("live-bytes"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// 此刻（连接仍打开）字节数应已非零。out 方向的 count 与客户端
	// 读到回显之间存在调度窗口，短暂等待两侧 goroutine 落账。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		met.mu.Lock()
		in, out := met.in, met.out
		met.mu.Unlock()
		if in > 0 && out > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("live bytes = in:%d out:%d, want 双向均 > 0", met.in, met.out)
}
