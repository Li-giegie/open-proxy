package admin

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Li-giegie/open-proxy/internal/netutil"
)

// startTCPEcho 启动一个原样回显的 TCP 服务并返回其地址。
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// tcpRoundtrip 对 addr 做一次写读回显。
func tcpRoundtrip(t *testing.T, addr, msg string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Errorf("echo = %q, want %q", buf, msg)
	}
}

// deadAddr 返回一个确定无监听的地址。
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// ---------- relay 资源 ----------

func TestCreateRelayAndRelayThrough(t *testing.T) {
	echo := startTCPEcho(t)
	_, api := newTestManager(t)

	view := createResource(t, api, map[string]any{
		"name":    "测试中继",
		"type":    TypeRelay,
		"address": "127.0.0.1:0",
		"relay": map[string]any{
			"upstreams": []any{
				map[string]any{"address": deadAddr(t), "weight": 5}, // 拨号失败 → failover
				map[string]any{"address": echo, "weight": 1},
			},
		},
	})
	if view.Status != StatusRunning {
		t.Fatalf("status = %q, want running", view.Status)
	}
	if view.Relay == nil || len(view.Relay.Upstreams) != 2 {
		t.Fatalf("relay spec = %+v", view.Relay)
	}

	// 多轮连接都经 failover 落到健康上游
	for i := 0; i < 3; i++ {
		tcpRoundtrip(t, view.Address, "admin-relay-ok")
	}
}

// TestCreateRelayInvalid 验证非法 relay 配置创建报 400。
func TestCreateRelayInvalid(t *testing.T) {
	_, api := newTestManager(t)

	cases := []map[string]any{
		{"name": "无上游", "type": TypeRelay, "address": "127.0.0.1:0", "relay": map[string]any{}},
		{"name": "缺spec", "type": TypeRelay, "address": "127.0.0.1:0"},
		{"name": "空地址", "type": TypeRelay, "address": "127.0.0.1:0",
			"relay": map[string]any{"upstreams": []any{map[string]any{"weight": 1}}}},
		{"name": "坏时长", "type": TypeRelay, "address": "127.0.0.1:0",
			"relay": map[string]any{"dial_timeout": "xx", "upstreams": []any{map[string]any{"address": "127.0.0.1:1"}}}},
	}
	for _, body := range cases {
		data, _ := json.Marshal(body)
		resp, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create %v: status = %d, want 400", body["name"], resp.StatusCode)
		}
	}
}

// TestRelayStopStart 验证中继资源的停止与再启动。
func TestRelayStopStart(t *testing.T) {
	echo := startTCPEcho(t)
	m, api := newTestManager(t)

	view := createResource(t, api, map[string]any{
		"name":    "中继启停",
		"type":    TypeRelay,
		"address": "127.0.0.1:0",
		"relay":   map[string]any{"upstreams": []any{map[string]any{"address": echo}}},
	})

	// 停止：连接被拒
	if _, err := m.Stop(view.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", view.Address, time.Second); err == nil {
		t.Errorf("dial should fail after stop")
	}

	// 再启动：恢复服务
	if _, err := m.Start(view.ID); err != nil {
		t.Fatal(err)
	}
	tcpRoundtrip(t, view.Address, "restart-ok")
}

// TestCreateRelayListenTLS 验证以 PEM 内容配置监听端 TLS 的中继。
func TestCreateRelayListenTLS(t *testing.T) {
	echo := startTCPEcho(t)

	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "relay", true)

	_, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name":    "TLS 中继",
		"type":    TypeRelay,
		"address": "127.0.0.1:0",
		"relay": map[string]any{
			"upstreams": []any{map[string]any{"address": echo}},
			"cert":      string(srvCertPEM),
			"key":       string(srvKeyPEM),
		},
	})

	pool := x509Pool(caPEM)
	conn, err := tlsDial(view.Address, pool)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("relay-tls-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("relay-tls-ok"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "relay-tls-ok" {
		t.Errorf("echo = %q", buf)
	}
}

// ---------- socks5 资源 ----------

// socks5Connect 极简 SOCKS5 客户端：握手（按需认证）+ CONNECT，
// 返回隧道连接与回复码。
func socks5Connect(t *testing.T, addr, user, password, target string) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	var methods []byte
	if user != "" {
		methods = []byte{0, 2}
	} else {
		methods = []byte{0}
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] == 2 { // 用户名/密码子协商
		up := append([]byte{1, byte(len(user))}, user...)
		up = append(up, byte(len(password)))
		up = append(up, password...)
		if _, err := conn.Write(up); err != nil {
			t.Fatal(err)
		}
		status := make([]byte, 2)
		if _, err := io.ReadFull(conn, status); err != nil {
			t.Fatal(err)
		}
		if status[1] != 0 {
			return conn, status[1]
		}
	}

	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}
	if net.ParseIP(host) == nil { // 域名目标
		req = []byte{5, 1, 0, 3, byte(len(host))}
		req = append(req, host...)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], uint16(port))
		req = append(req, p[:]...)
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	rhead := make([]byte, 4)
	if _, err := io.ReadFull(conn, rhead); err != nil {
		t.Fatal(err)
	}
	// 跳过变长 BND.ADDR + 端口
	switch rhead[3] {
	case 1:
		io.CopyN(io.Discard, conn, 6)
	case 4:
		io.CopyN(io.Discard, conn, 18)
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(conn, n); err != nil {
			t.Fatal(err)
		}
		io.CopyN(io.Discard, conn, int64(n[0])+2)
	}
	return conn, rhead[1]
}

func TestCreateSocks5AndProxyThrough(t *testing.T) {
	echo := startTCPEcho(t)
	_, api := newTestManager(t)

	view := createResource(t, api, map[string]any{
		"name":    "测试 SOCKS5",
		"type":    TypeSocks5,
		"address": "127.0.0.1:0",
		"socks5":  map[string]any{"user": "alice", "password": "s3cret"},
	})
	if view.Status != StatusRunning {
		t.Fatalf("status = %q, want running", view.Status)
	}
	if view.Socks5 == nil || view.Socks5.User != "alice" {
		t.Fatalf("socks5 spec = %+v", view.Socks5)
	}

	// 正确凭证：CONNECT 建立后隧道内透传
	conn, rep := socks5Connect(t, view.Address, "alice", "s3cret", echo)
	if rep != 0 {
		t.Fatalf("reply = %d, want 0", rep)
	}
	if _, err := conn.Write([]byte("socks-admin-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("socks-admin-ok"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "socks-admin-ok" {
		t.Errorf("echo = %q", buf)
	}
	conn.Close()

	// 错误密码：子协商失败
	conn, rep = socks5Connect(t, view.Address, "alice", "wrong", echo)
	conn.Close()
	if rep == 0 {
		t.Errorf("wrong password should fail subnegotiation")
	}
}

// TestCreateSocks5Open 无认证开放代理。
func TestCreateSocks5Open(t *testing.T) {
	echo := startTCPEcho(t)
	_, api := newTestManager(t)

	view := createResource(t, api, map[string]any{
		"name":    "开放 SOCKS5",
		"type":    TypeSocks5,
		"address": "127.0.0.1:0",
		"socks5":  map[string]any{},
	})
	conn, rep := socks5Connect(t, view.Address, "", "", echo)
	if rep != 0 {
		t.Fatalf("reply = %d, want 0", rep)
	}
	if _, err := conn.Write([]byte("open-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("open-ok"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "open-ok" {
		t.Errorf("echo = %q", buf)
	}
	conn.Close()
}

// TestCreateSocks5Invalid 验证非法 socks5 配置创建报 400。
func TestCreateSocks5Invalid(t *testing.T) {
	_, api := newTestManager(t)

	data, _ := json.Marshal(map[string]any{
		"name": "半认证", "type": TypeSocks5, "address": "127.0.0.1:0",
		"socks5": map[string]any{"user": "u"},
	})
	resp, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// ---------- 共享小工具 ----------

// x509Pool 从 PEM 构建 CA 池。
func x509Pool(caPEM []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return pool
}

// tlsDial 以信任 pool 的 TLS 客户端拨号。
func tlsDial(addr string, pool *x509.CertPool) (net.Conn, error) {
	return tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
}

// TestCreateRelayPerUpstreamTLS 验证各上游的 TLS 配置独立生效：
// 一个 mTLS 上游与一个明文上游并存，两种连接都能建立并透传。
func TestCreateRelayPerUpstreamTLS(t *testing.T) {
	caPEM, ca, caKey := netutil.GenCA(t)

	// mTLS echo 上游：要求客户端证书，连上即写标记 'T'
	upCertPEM, upCertKeyPEM := netutil.GenLeaf(t, ca, caKey, "up-mtls", true)
	upCert, err := tls.X509KeyPair(upCertPEM, upCertKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	relayCliPEM, relayCliKey := netutil.GenLeaf(t, ca, caKey, "relay-cli", false)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	mtlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(mtlsLn, &tls.Config{
		Certificates: []tls.Certificate{upCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); conn.Write([]byte{'T'}) }()
		}
	}()
	t.Cleanup(func() { tlsLn.Close() })

	// 明文上游：连上即写标记 'P'
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := plainLn.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); conn.Write([]byte{'P'}) }()
		}
	}()
	t.Cleanup(func() { plainLn.Close() })

	_, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name":    "混合上游",
		"type":    TypeRelay,
		"address": "127.0.0.1:0",
		"relay": map[string]any{
			"upstreams": []any{
				map[string]any{ // mTLS 上游：独立的 CA/cert/key
					"address": tlsLn.Addr().String(),
					"weight":  1,
					"ca":      string(caPEM),
					"cert":    string(relayCliPEM),
					"key":     string(relayCliKey),
				},
				map[string]any{ // 明文上游：无 TLS 字段
					"address": plainLn.Addr().String(),
					"weight":  1,
				},
			},
		},
	})

	// 多条连接，两个上游按 1:1 权重都应被命中
	hits := map[byte]int{}
	for i := 0; i < 40; i++ {
		conn, err := net.DialTimeout("tcp", view.Address, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		var tag [1]byte
		if _, err := io.ReadFull(conn, tag[:]); err != nil {
			t.Fatal(err)
		}
		hits[tag[0]]++
		conn.Close()
	}
	if hits['T'] == 0 || hits['P'] == 0 {
		t.Errorf("per-upstream TLS: mTLS upstream hits=%d, plain upstream hits=%d, want both > 0", hits['T'], hits['P'])
	}
}

// updateResource 通过 API 编辑资源，返回更新后的视图。
func updateResource(t *testing.T, api *httptest.Server, id string, body any) View {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, api.URL+"/api/resources/"+id, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update: status = %d, body = %s", resp.StatusCode, raw)
	}
	var view View
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

// TestUpdateRelay 验证编辑中继：改上游列表即时生效（重启实例）、
// 改地址重新绑定、非法编辑 400 且旧实例不受影响。
func TestUpdateRelay(t *testing.T) {
	echoA, echoB := startTCPEcho(t), startTCPEcho(t)
	_, api := newTestManager(t)

	// 创建：上游 A
	view := createResource(t, api, map[string]any{
		"name": "编辑中继", "type": TypeRelay, "address": "127.0.0.1:0",
		"relay": map[string]any{"upstreams": []any{map[string]any{"address": echoA}}},
	})
	tcpRoundtrip(t, view.Address, "before-update")

	// 编辑：换上游 B，流量改走 B
	updated := updateResource(t, api, view.ID, map[string]any{
		"name": "编辑中继", "type": TypeRelay, "address": view.Address,
		"relay": map[string]any{"upstreams": []any{map[string]any{"address": echoB}}},
	})
	if updated.Status != StatusRunning {
		t.Fatalf("status = %q, want running", updated.Status)
	}
	tcpRoundtrip(t, view.Address, "after-update")

	// 编辑：换地址（端口 0 重新随机分配）
	moved := updateResource(t, api, view.ID, map[string]any{
		"name": "编辑中继", "type": TypeRelay, "address": "127.0.0.1:0",
		"relay": map[string]any{"upstreams": []any{map[string]any{"address": echoA}}},
	})
	if moved.Address == view.Address {
		t.Fatalf("地址未变化: %s", moved.Address)
	}
	tcpRoundtrip(t, moved.Address, "after-move")

	// 非法编辑（无上游）：400，旧实例仍在服务
	bad, _ := json.Marshal(map[string]any{
		"name": "坏编辑", "type": TypeRelay, "address": moved.Address,
		"relay": map[string]any{},
	})
	req, _ := http.NewRequest(http.MethodPut, api.URL+"/api/resources/"+view.ID, bytes.NewReader(bad))
	req.Header.Set("Content-Type", "application/json")
	resp, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad update: status = %d, want 400", resp.StatusCode)
	}
	tcpRoundtrip(t, moved.Address, "after-bad-update")

	// 编辑不存在的资源：404
	bad2, _ := json.Marshal(map[string]any{"name": "x", "type": TypeRelay, "address": "127.0.0.1:1",
		"relay": map[string]any{"upstreams": []any{map[string]any{"address": "127.0.0.1:1"}}}})
	req2, _ := http.NewRequest(http.MethodPut, api.URL+"/api/resources/no-such-id", bytes.NewReader(bad2))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := api.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("update missing: status = %d, want 404", resp2.StatusCode)
	}
}

// TestUpdateStoppedResource 验证编辑已停止的资源：只改配置不启动。
func TestUpdateStoppedResource(t *testing.T) {
	echo := startTCPEcho(t)
	m, api := newTestManager(t)

	view := createResource(t, api, map[string]any{
		"name": "停用中继", "type": TypeRelay, "address": "127.0.0.1:0",
		"relay": map[string]any{"upstreams": []any{map[string]any{"address": echo}}},
	})
	if _, err := m.Stop(view.ID); err != nil {
		t.Fatal(err)
	}

	updated := updateResource(t, api, view.ID, map[string]any{
		"name": "停用中继-改名", "type": TypeRelay, "address": view.Address,
		"relay": map[string]any{"upstreams": []any{map[string]any{"address": echo}}},
	})
	if updated.Status != StatusStopped {
		t.Fatalf("status = %q, want stopped（编辑不应启动已停止的资源）", updated.Status)
	}
	if updated.Name != "停用中继-改名" {
		t.Errorf("name = %q", updated.Name)
	}

	// 再启动用新配置
	if _, err := m.Start(view.ID); err != nil {
		t.Fatal(err)
	}
	tcpRoundtrip(t, view.Address, "start-after-update")
}

// TestUpdateForwardKeepsUsers 验证编辑 forward 保留 users 列表
// （UI 不展示 salt/hash 形式的动态用户，整份提交时由调用方带回）。
func TestUpdateForwardKeepsUsers(t *testing.T) {
	_, api := newTestManager(t)
	view := createResource(t, api, map[string]any{
		"name": "多用户正向", "type": TypeForward, "address": "127.0.0.1:0",
		"forward": map[string]any{"users": []any{
			map[string]any{"user": "u1", "password": "p1"},
			map[string]any{"user": "u2", "password": "p2"},
		}},
	})

	// 编辑：改名称并带回原 users（模拟 UI 的提交行为）
	fwd := view.Forward
	updateResource(t, api, view.ID, map[string]any{
		"name": "多用户正向-改名", "type": TypeForward, "address": view.Address,
		"forward": map[string]any{"users": fwd.Users},
	})

	updated, ok := m2Get(t, api, view.ID)
	if !ok {
		t.Fatal("resource missing")
	}
	if len(updated.Forward.Users) != 2 {
		t.Fatalf("users = %v, want 2 条保留", updated.Forward.Users)
	}
	if updated.Forward.Users[0].Salt == "" || updated.Forward.Users[0].Hash == "" {
		t.Errorf("用户摘要丢失（明文密码应已转为 salt/hash）")
	}
	if updated.Name != "多用户正向-改名" {
		t.Errorf("name = %q", updated.Name)
	}
}

// m2Get 经 API 读取单个资源视图。
func m2Get(t *testing.T, api *httptest.Server, id string) (View, bool) {
	t.Helper()
	resp, err := api.Client().Get(api.URL + "/api/resources")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var views []View
	if err := json.NewDecoder(resp.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if v.ID == id {
			return v, true
		}
	}
	return View{}, false
}

// TestForwardResourceHTTP1OnlyALPN 验证经管理中心创建的资源：
// forward 因 CONNECT 依赖 Hijack 仅协商 http/1.1；reverse 不劫持连接，
// 保留 h2（对照组）。
func TestForwardResourceHTTP1OnlyALPN(t *testing.T) {
	caPEM, ca, caKey := netutil.GenCA(t)
	srvPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "res", true)
	pool := x509Pool(caPEM)

	_, api := newTestManager(t)
	// forward 资源（监听 TLS）
	fwd := createResource(t, api, map[string]any{
		"name": "alpn-forward", "type": TypeForward, "address": "127.0.0.1:0",
		"forward": map[string]any{
			"user": "u", "password": "p",
			"cert": string(srvPEM), "key": string(srvKeyPEM),
		},
	})
	conn, err := tls.Dial("tcp", fwd.Address, &tls.Config{
		RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("forward tls dial: %v", err)
	}
	conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("forward ALPN = %q, want http/1.1", got)
	}

	// reverse 资源（监听 TLS）：不限制协议，h2 可协商
	rev := createResource(t, api, map[string]any{
		"name": "alpn-reverse", "type": TypeReverse, "address": "127.0.0.1:0",
		"reverse": map[string]any{
			"backends": []string{"http://127.0.0.1:1"},
			"cert":     string(srvPEM), "key": string(srvKeyPEM),
		},
	})
	conn2, err := tls.Dial("tcp", rev.Address, &tls.Config{
		RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("reverse tls dial: %v", err)
	}
	conn2.Close()
	if got := conn2.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("reverse ALPN = %q, want h2", got)
	}
}
