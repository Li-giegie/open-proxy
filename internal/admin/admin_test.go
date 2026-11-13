package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// newTestManager 返回绑定临时存储文件的管理中心与暴露其 API 的测试服务。
func newTestManager(t *testing.T) (*Manager, *httptest.Server) {
	t.Helper()
	m, err := NewManager(NewStore(filepath.Join(t.TempDir(), "proxies.json")), nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(Handler(m, "", ""))
	t.Cleanup(api.Close)
	return m, api
}

// createResource 通过 API 创建资源，返回实际监听地址。
func createResource(t *testing.T, api *httptest.Server, body any) View {
	t.Helper()
	data, _ := json.Marshal(body)
	resp, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status = %d, body = %s", resp.StatusCode, raw)
	}
	var view View
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func TestCreateForwardAndProxyThrough(t *testing.T) {
	var gotPath, gotXFF string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotXFF = r.URL.Path, r.Header.Get("X-Forwarded-For")
		w.Write([]byte("forward-ok"))
	}))
	defer target.Close()

	_, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name":    "测试正向",
		"type":    TypeForward,
		"address": "127.0.0.1:0",
		"forward": map[string]any{"user": "u", "password": "p"},
	})
	if view.Status != StatusRunning {
		t.Fatalf("status = %q, want running", view.Status)
	}

	// 经该资源代理访问目标：代理 URL 带 userinfo 自动完成 Basic 认证
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustURL(t, "http://u:p@"+view.Address)),
	}}
	resp, err := client.Get(target.URL + "/proxied")
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "forward-ok" {
		t.Errorf("resp = %d %q", resp.StatusCode, body)
	}
	if gotPath != "/proxied" || gotXFF == "" {
		t.Errorf("target saw path=%q xff=%q", gotPath, gotXFF)
	}

	// 不带凭证：407
	noAuth := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustURL(t, "http://"+view.Address)),
	}}
	resp, err = noAuth.Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("no auth: status = %d, want 407", resp.StatusCode)
	}
}

func TestCreateReverseAndProxyThrough(t *testing.T) {
	var gotHost, gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotXFF = r.Host, r.Header.Get("X-Forwarded-For")
		w.Write([]byte("reverse-ok"))
	}))
	defer backend.Close()

	_, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name":    "测试反向",
		"type":    TypeReverse,
		"address": "127.0.0.1:0",
		"reverse": map[string]any{"backends": []string{backend.URL}},
	})

	// 反向代理语义：直接访问资源地址，Host 透传、附加 XFF
	req, _ := http.NewRequest(http.MethodGet, "http://"+view.Address+"/", nil)
	req.Host = "app.example.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "reverse-ok" {
		t.Errorf("resp = %d %q", resp.StatusCode, body)
	}
	if gotHost != "app.example.com" {
		t.Errorf("backend Host = %q, want app.example.com", gotHost)
	}
	if gotXFF == "" {
		t.Errorf("backend missing X-Forwarded-For")
	}
}

func TestStopStartDelete(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	m, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name": "生命周期", "type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{},
	})

	// 停止：端口不再监听
	do := func(method, path string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, api.URL+path, nil)
		resp, err := api.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := do("POST", "/api/resources/"+view.ID+"/stop")
	resp.Body.Close()
	if v, _ := m.Get(view.ID); v.Status != StatusStopped {
		t.Fatalf("stop: status = %q, want stopped", v.Status)
	}
	if conn, err := net.Dial("tcp", view.Address); err == nil {
		conn.Close()
		t.Fatalf("停止后端口 %s 仍在监听", view.Address)
	}

	// 再次启动：恢复服务
	resp = do("POST", "/api/resources/"+view.ID+"/start")
	resp.Body.Close()
	started, _ := m.Get(view.ID)
	if started.Status != StatusRunning {
		t.Fatalf("start: status = %q, want running", started.Status)
	}
	if conn, err := net.Dial("tcp", started.Address); err != nil {
		t.Fatalf("启动后端口 %s 未监听: %v", started.Address, err)
	} else {
		conn.Close()
	}

	// 删除：404
	resp = do("DELETE", "/api/resources/"+view.ID)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: status = %d, want 204", resp.StatusCode)
	}
	if v, ok := m.Get(view.ID); ok {
		t.Fatalf("删除后资源仍存在: %+v", v)
	}
	resp = do("POST", "/api/resources/"+view.ID+"/start")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("start deleted: status = %d, want 404", resp.StatusCode)
	}
}

func TestPersistenceRestore(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	dataFile := filepath.Join(t.TempDir(), "proxies.json")
	mgr1, err := NewManager(NewStore(dataFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	apiA := httptest.NewServer(Handler(mgr1, "", ""))
	defer apiA.Close()
	view := createResource(t, apiA, map[string]any{
		"name": "持久化", "type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{},
	})

	// 模拟旧进程退出：停掉实例（配置仍在数据文件里）
	if _, err := mgr1.Stop(view.ID); err != nil {
		t.Fatal(err)
	}

	// 用同一数据文件重建管理中心：资源应恢复并运行
	mgr2, err := NewManager(NewStore(dataFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	views := mgr2.List()
	if len(views) != 1 {
		t.Fatalf("恢复后资源数 = %d, want 1", len(views))
	}
	if views[0].ID != view.ID || views[0].Status != StatusRunning {
		t.Errorf("恢复后 = id %s status %q, want id %s running", views[0].ID, views[0].Status, view.ID)
	}

	// 恢复的资源确实可服务
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustURL(t, "http://"+views[0].Address)),
	}}
	resp, err := client.Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("restored proxy: status = %d", resp.StatusCode)
	}
}

func TestCreateValidation(t *testing.T) {
	_, api := newTestManager(t)

	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"未知类型", map[string]any{"name": "x", "type": "socks", "address": "127.0.0.1:0"}, "未知资源类型"},
		{"缺名称", map[string]any{"type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{}}, "name"},
		{"缺地址", map[string]any{"name": "x", "type": TypeForward, "forward": map[string]any{}}, "address"},
		{"认证只有用户名", map[string]any{"name": "x", "type": TypeForward, "address": "127.0.0.1:0",
			"forward": map[string]any{"user": "u"}}, "必须同时设置"},
		{"反向缺 backends", map[string]any{"name": "x", "type": TypeReverse, "address": "127.0.0.1:0",
			"reverse": map[string]any{}}, "backends"},
		{"上游 scheme 非法", map[string]any{"name": "x", "type": TypeForward, "address": "127.0.0.1:0",
			"forward": map[string]any{"upstream": "ftp://h:1"}}, "无效的 upstream"},
		{"http 上游配 TLS", map[string]any{"name": "x", "type": TypeForward, "address": "127.0.0.1:0",
			"forward": map[string]any{"upstream": "http://127.0.0.1:1", "upstream_ca": "x.pem"}}, "仅适用于 https"},
	}
	for _, c := range cases {
		data, _ := json.Marshal(c.body)
		resp, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400（body=%s）", c.name, resp.StatusCode, raw)
		}
		var errResp map[string]string
		_ = json.Unmarshal(raw, &errResp)
		if !strings.Contains(errResp["error"], c.want) {
			t.Errorf("%s: error = %q, want 含 %q", c.name, errResp["error"], c.want)
		}
	}

	// 非法 JSON
	resp, err := api.Client().Post(api.URL+"/api/resources", "application/json", strings.NewReader("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", resp.StatusCode)
	}
}

func TestAddressConflict(t *testing.T) {
	m, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name": "先占", "type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{},
	})
	// 占用其端口再创建：应 400，且资源不落库
	data, _ := json.Marshal(map[string]any{
		"name": "冲突", "type": TypeForward, "address": view.Address, "forward": map[string]any{},
	})
	resp, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("conflict: status = %d, want 400", resp.StatusCode)
	}
	if got := len(m.List()); got != 1 {
		t.Errorf("资源数 = %d, want 1", got)
	}
}

func TestBasicAuth(t *testing.T) {
	m, err := NewManager(NewStore(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(Handler(m, "admin", "s3cret"))
	defer api.Close()

	// 静态页面不需要认证（避免浏览器原生弹框），登录逻辑在前端完成
	resp, err := http.Get(api.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("static page: status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("管理中心")) {
		t.Fatalf("static page content missing")
	}

	// 无凭证访问 API：401 + 挑战头
	resp, err = http.Get(api.URL + "/api/resources")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth: status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Errorf("missing WWW-Authenticate")
	}

	// Basic 直接访问 API：可用
	req, _ := http.NewRequest("GET", api.URL+"/api/resources", nil)
	req.SetBasicAuth("admin", "s3cret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("basic auth: status = %d, want 200", resp.StatusCode)
	}

	// 错误凭证：401
	req.SetBasicAuth("admin", "wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: status = %d, want 401", resp.StatusCode)
	}
}

// TestLoginSession 验证登录会话：/api/login 换取 Bearer 令牌、令牌访问
// API、错误凭证被拒、登出后令牌失效。
func TestLoginSession(t *testing.T) {
	m, err := NewManager(NewStore(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(Handler(m, "admin", "s3cret"))
	defer api.Close()

	login := func(user, password string) (int, map[string]any) {
		data, _ := json.Marshal(map[string]string{"user": user, "password": password})
		resp, err := api.Client().Post(api.URL+"/api/login", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// 错误凭证
	code, out := login("admin", "wrong")
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong login: status = %d, want 401", code)
	}

	// 正确凭证 → 令牌
	code, out = login("admin", "s3cret")
	if code != http.StatusOK || out["token"] == "" {
		t.Fatalf("login: status = %d, out = %v", code, out)
	}
	token := out["token"].(string)

	// Bearer 令牌访问 API
	req, _ := http.NewRequest("GET", api.URL+"/api/resources", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer: status = %d, want 200", resp.StatusCode)
	}

	// 登出后令牌失效
	req, _ = http.NewRequest("DELETE", api.URL+"/api/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want 204", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", api.URL+"/api/resources", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token after logout: status = %d, want 401", resp.StatusCode)
	}
}

// TestNoAuthOpen 验证未配置认证时全开放：静态页与 API 均直接可用，
// 登录接口返回 auth=false（前端据此跳过登录页）。
func TestNoAuthOpen(t *testing.T) {
	m, err := NewManager(NewStore(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(Handler(m, "", ""))
	defer api.Close()

	resp, err := http.Get(api.URL + "/api/resources")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no auth api: status = %d, want 200", resp.StatusCode)
	}

	resp2, err := api.Client().Post(api.URL+"/api/login", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&out)
	if resp2.StatusCode != http.StatusOK || out["auth"] != false {
		t.Errorf("no auth login: status = %d out = %v, want 200 auth=false", resp2.StatusCode, out)
	}
}

func TestCreateForwardChainResource(t *testing.T) {
	// 通过 API 创建"本地 → 上游"代理链资源，验证管理中心组装的链可用
	var sawHost string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost = r.Host
		w.Write([]byte("chain-ok"))
	}))
	defer target.Close()

	_, api := newTestManager(t)
	upstreamView := createResource(t, api, map[string]any{
		"name": "上游", "type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{},
	})
	localView := createResource(t, api, map[string]any{
		"name": "本地链", "type": TypeForward, "address": "127.0.0.1:0",
		"forward": map[string]any{"upstream": "http://" + upstreamView.Address},
	})

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustURL(t, "http://"+localView.Address)),
	}}
	resp, err := client.Get(target.URL + "/")
	if err != nil {
		t.Fatalf("chain request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "chain-ok" {
		t.Errorf("resp = %d %q", resp.StatusCode, body)
	}
	bu := mustURL(t, target.URL)
	if sawHost != bu.Host {
		t.Errorf("target host = %q, want %q", sawHost, bu.Host)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
