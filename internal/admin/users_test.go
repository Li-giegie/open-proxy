package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// proxyClientFor 返回经 addr 代理（可选 userinfo 认证）的 HTTP 客户端。
func proxyClientFor(proxyURL string) *http.Client {
	u, _ := url.Parse(proxyURL)
	return &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(u),
	}}
}

// addUserViaAPI 经 API 为资源添加用户。
func addUserViaAPI(t *testing.T, api *httptest.Server, id, user, password string) {
	t.Helper()
	data, _ := json.Marshal(map[string]string{"user": user, "password": password})
	resp, err := api.Client().Post(api.URL+"/api/resources/"+id+"/users", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add user %s: status = %d, body = %s", user, resp.StatusCode, raw)
	}
}

// storeFileOf 返回测试 Manager 的持久化文件内容。
func storeFileOf(t *testing.T, m *Manager) []byte {
	t.Helper()
	raw, err := os.ReadFile(m.store.path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestUserManagement 验证动态用户管理：无认证资源加用户后需要认证、
// 运行中即时增删生效、密码明文不落盘。
func TestUserManagement(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	m, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name": "用户管理", "type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{},
	})

	// 初始：开放代理，直接可用
	resp, err := proxyClientFor("http://" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open proxy: status = %d", resp.StatusCode)
	}

	// 添加用户：alice 与 bob（首次添加触发实例重启挂上认证器）
	addUserViaAPI(t, api, view.ID, "alice", "pw1")
	addUserViaAPI(t, api, view.ID, "bob", "pw2")

	users, err := m.Users(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0] != "alice" || users[1] != "bob" {
		t.Errorf("users = %v, want [alice bob]", users)
	}

	// alice/bob 可用，无凭证与错误密码被拒
	for _, cred := range []string{"alice:pw1", "bob:pw2"} {
		resp, err := proxyClientFor("http://" + cred + "@" + view.Address).Get(target.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", cred, resp.StatusCode)
		}
	}
	resp, err = proxyClientFor("http://" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("no creds: status = %d, want 407", resp.StatusCode)
	}
	resp, err = proxyClientFor("http://alice:wrong@" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("wrong password: status = %d, want 407", resp.StatusCode)
	}

	// 删除 alice：运行中即时生效
	req, _ := http.NewRequest("DELETE", api.URL+"/api/resources/"+view.ID+"/users/alice", nil)
	resp, err = api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("remove user: status = %d", resp.StatusCode)
	}
	resp, err = proxyClientFor("http://alice:pw1@" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("removed alice: status = %d, want 407", resp.StatusCode)
	}

	// 覆盖密码：旧密码失效
	addUserViaAPI(t, api, view.ID, "bob", "pw3")
	resp, err = proxyClientFor("http://bob:pw2@" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("old password: status = %d, want 407", resp.StatusCode)
	}

	// 明文密码绝不落盘
	raw := storeFileOf(t, m)
	for _, plaintext := range []string{"pw1", "pw2", "pw3"} {
		if bytes.Contains(raw, []byte(plaintext)) {
			t.Errorf("持久化文件泄露明文密码 %q", plaintext)
		}
	}
}

// TestUserManagementInitialUsers 验证创建时直接带用户列表（明文密码
// 只在请求中存在，落库前转为摘要）。
func TestUserManagementInitialUsers(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	m, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name": "带用户创建", "type": TypeForward, "address": "127.0.0.1:0",
		"forward": map[string]any{"users": []map[string]string{
			{"user": "carol", "password": "secret9"},
		}},
	})

	resp, err := proxyClientFor("http://carol:secret9@" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("carol: status = %d, want 200", resp.StatusCode)
	}
	resp, err = proxyClientFor("http://" + view.Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("no creds: status = %d, want 407", resp.StatusCode)
	}

	if bytes.Contains(storeFileOf(t, m), []byte("secret9")) {
		t.Errorf("持久化文件泄露明文密码")
	}
}

// TestUserPersistenceAcrossRestart 验证用户随资源持久化并在重启后恢复。
func TestUserPersistenceAcrossRestart(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer target.Close()

	dataFile := filepath.Join(t.TempDir(), "proxies.json")
	mgr, err := NewManager(NewStore(dataFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(Handler(mgr, "", ""))
	defer api.Close()
	view := createResource(t, api, map[string]any{
		"name": "用户持久化", "type": TypeForward, "address": "127.0.0.1:0",
		"forward": map[string]any{"users": []map[string]string{
			{"user": "erin", "password": "pw9"},
		}},
	})
	if _, err := mgr.Stop(view.ID); err != nil {
		t.Fatal(err)
	}

	mgr2, err := NewManager(NewStore(dataFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	views := mgr2.List()
	if len(views) != 1 {
		t.Fatalf("恢复后资源数 = %d, want 1", len(views))
	}
	resp, err := proxyClientFor("http://erin:pw9@" + views[0].Address).Get(target.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("restored user auth: status = %d, want 200", resp.StatusCode)
	}
}

// TestUserManagementValidation 验证用户管理的错误处理。
func TestUserManagementValidation(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	_, api := newTestManager(t)
	fwd := createResource(t, api, map[string]any{
		"name": "校验", "type": TypeForward, "address": "127.0.0.1:0", "forward": map[string]any{},
	})
	rev := createResource(t, api, map[string]any{
		"name": "反向", "type": TypeReverse, "address": "127.0.0.1:0",
		"reverse": map[string]any{"backends": []string{target.URL}},
	})

	// 反向资源不支持用户管理
	data, _ := json.Marshal(map[string]string{"user": "u", "password": "p"})
	resp, err := api.Client().Post(api.URL+"/api/resources/"+rev.ID+"/users", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reverse users: status = %d, want 400", resp.StatusCode)
	}

	// 空用户名/密码
	for _, body := range []map[string]string{{"user": "", "password": "p"}, {"user": "u", "password": ""}} {
		data, _ := json.Marshal(body)
		resp, err := api.Client().Post(api.URL+"/api/resources/"+fwd.ID+"/users", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid body %v: status = %d, want 400", body, resp.StatusCode)
		}
	}

	// 删除不存在的用户：404
	req, _ := http.NewRequest("DELETE", api.URL+"/api/resources/"+fwd.ID+"/users/nobody", nil)
	resp, err = api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("remove unknown: status = %d, want 404", resp.StatusCode)
	}

	// 空用户列表必须序列化为 []（null 会让前端 .length 抛错）
	resp, err = api.Client().Get(api.URL + "/api/resources/" + fwd.ID + "/users")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(bytes.TrimSpace(raw)) != "[]" {
		t.Errorf("empty users = %q, want []", raw)
	}
}

// TestMetricsEndpoint 验证监控 API：正向资源统计按用户请求数与字节
// （407 不计入），反向资源统计状态码与响应字节，列表内联简要指标。
func TestMetricsEndpoint(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("metrics-body"))
	}))
	defer target.Close()

	_, api := newTestManager(t)
	fwd := createResource(t, api, map[string]any{
		"name": "监控正向", "type": TypeForward, "address": "127.0.0.1:0",
		"forward": map[string]any{"user": "dave", "password": "pw"},
	})
	rev := createResource(t, api, map[string]any{
		"name": "监控反向", "type": TypeReverse, "address": "127.0.0.1:0",
		"reverse": map[string]any{"backends": []string{target.URL}},
	})

	// 正向：dave 发 2 个请求；无凭证被拒（不应计入）
	client := proxyClientFor("http://dave:pw@" + fwd.Address)
	for i := 0; i < 2; i++ {
		resp, err := client.Get(target.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	resp, _ := proxyClientFor("http://" + fwd.Address).Get(target.URL + "/")
	resp.Body.Close()

	// 反向：3 个请求
	for i := 0; i < 3; i++ {
		resp, err := http.Get("http://" + rev.Address + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	fetchMetrics := func(id string) MetricsView {
		t.Helper()
		resp, err := api.Client().Get(api.URL + "/api/resources/" + id + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var view MetricsView
		if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
			t.Fatal(err)
		}
		return view
	}

	fm := fetchMetrics(fwd.ID)
	if fm.Requests != 2 {
		t.Errorf("forward requests = %d, want 2（407 不应计入）", fm.Requests)
	}
	if fm.ByUser["dave"] != 2 {
		t.Errorf("by_user[dave] = %d, want 2", fm.ByUser["dave"])
	}
	if fm.BytesOut < int64(2*len("metrics-body")) {
		t.Errorf("bytes_out = %d, want >= %d", fm.BytesOut, 2*len("metrics-body"))
	}
	if fm.ByStatus["200"] != 2 {
		t.Errorf("by_status[200] = %d, want 2", fm.ByStatus["200"])
	}
	if len(fm.Recent) != 2 || fm.Recent[0].User != "dave" {
		t.Errorf("recent = %+v, want 2 条 dave 的记录", fm.Recent)
	}

	rm := fetchMetrics(rev.ID)
	if rm.Requests != 3 {
		t.Errorf("reverse requests = %d, want 3", rm.Requests)
	}
	if rm.ByStatus["200"] != 3 {
		t.Errorf("reverse by_status[200] = %d, want 3", rm.ByStatus["200"])
	}
	if rm.BytesOut < int64(3*len("metrics-body")) {
		t.Errorf("reverse bytes_out = %d, want >= %d", rm.BytesOut, 3*len("metrics-body"))
	}

	// 列表视图内联简要指标
	list, err := listResources(api)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range list {
		if v.ID == fwd.ID && v.Requests != 2 {
			t.Errorf("list requests = %d, want 2", v.Requests)
		}
		if v.ID == rev.ID && v.BytesOut < int64(3*len("metrics-body")) {
			t.Errorf("list bytes_out = %d", v.BytesOut)
		}
	}
}

// listResources 经 API 获取资源列表。
func listResources(api *httptest.Server) ([]View, error) {
	resp, err := api.Client().Get(api.URL + "/api/resources")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var views []View
	return views, json.NewDecoder(resp.Body).Decode(&views)
}
