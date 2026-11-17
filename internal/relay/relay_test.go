package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Li-giegie/open-proxy/internal/netutil"
)

// ---------- 配置层测试 ----------

// writeConfig 把配置写成临时 JSON 文件，返回路径。
func writeConfig(t *testing.T, cfg any) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndValidate(t *testing.T) {
	// 正常配置
	path := writeConfig(t, Config{
		Listen:    "127.0.0.1:0",
		Upstreams: []UpstreamConfig{{Address: "127.0.0.1:9001", Weight: 1}},
	})
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:0" || len(cfg.Upstreams) != 1 {
		t.Errorf("cfg = %+v", cfg)
	}

	// 各类校验错误
	bad := []Config{
		{Upstreams: []UpstreamConfig{{Address: "a:1"}}},                                   // listen 为空
		{Listen: "127.0.0.1:0"},                                                           // 无上游
		{Listen: "127.0.0.1:0", Upstreams: []UpstreamConfig{{Weight: 1}}},                 // address 为空
		{Listen: "127.0.0.1:0", Upstreams: []UpstreamConfig{{Address: "a:1", Weight: 0}}}, // weight < 1
		{Listen: "127.0.0.1:0", Upstreams: []UpstreamConfig{{Address: "a:1", TLS: &ClientTLSSettings{CA: "x.pem"}}}, DialTimeout: "xx"}, // 非法时长
		{Listen: "127.0.0.1:0", Upstreams: []UpstreamConfig{{Address: "a:1", TLS: &ClientTLSSettings{Cert: "c.pem"}}}},                  // cert 无 key
		{Listen: "127.0.0.1:0", ListenTLS: &TLSSettings{Key: "k.pem"}, Upstreams: []UpstreamConfig{{Address: "a:1"}}},                   // listen cert 无 key
	}
	for i := range bad {
		if err := bad[i].Validate(); err == nil {
			t.Errorf("case %d: want error, cfg = %+v", i, bad[i])
		}
	}

	// 非法 JSON
	path = filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Errorf("bad json: want error")
	}
}

// ---------- 选择器单元测试 ----------

// TestPickWeighted 验证权重选择的边界与分布：全部权重集中时应确定性
// 命中，权重 1:1 时长期采样应大致均衡。
func TestPickWeighted(t *testing.T) {
	// 单候选与权重集中：必然命中
	one := []upstream{{address: "a", weight: 1}}
	for i := 0; i < 100; i++ {
		if pickWeighted(one) != 0 {
			t.Fatalf("single candidate: want 0")
		}
	}
	heavy := []upstream{{address: "a", weight: 100}, {address: "b", weight: 1}}
	hits := map[string]int{}
	for i := 0; i < 10000; i++ {
		hits[heavy[pickWeighted(heavy)].address]++
	}
	// 期望比例 100:1（约 9901/99），容差 ±5%
	if hits["a"] < 9400 || hits["a"] > 10400 {
		t.Errorf("weighted 100:1 → %v, want ~9901/99", hits)
	}

	// 1:1 均衡采样
	even := []upstream{{address: "a", weight: 1}, {address: "b", weight: 1}}
	hits = map[string]int{}
	for i := 0; i < 10000; i++ {
		hits[even[pickWeighted(even)].address]++
	}
	if hits["a"] < 4500 || hits["a"] > 5500 {
		t.Errorf("1:1 sampling too skewed: %v", hits)
	}
}

// ---------- 端到端测试 ----------

// startEcho 启动一个原样回显的 TCP 服务并返回其地址。
func startEcho(t *testing.T) string {
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

// startRelay 按配置启动中继并返回其监听地址（Serve 自带 TLS 包装）。
func startRelay(t *testing.T, cfg Config) string {
	t.Helper()
	cfg.Listen = "127.0.0.1:0"
	r, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = r.Serve(ln) }()
	t.Cleanup(func() { _ = r.Close() })
	return ln.Addr().String()
}

// relayRoundtrip 经中继做一次写读回显。
func relayRoundtrip(t *testing.T, addr string, msg string, tlsConf *tls.Config) {
	t.Helper()
	var conn net.Conn
	var err error
	if tlsConf != nil {
		conn, err = tls.Dial("tcp", addr, tlsConf)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
	}

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

func TestRelayPlaintext(t *testing.T) {
	echo := startEcho(t)
	relay := startRelay(t, Config{
		Upstreams: []UpstreamConfig{{Address: echo, Weight: 1}},
	})
	relayRoundtrip(t, relay, "plain-relay-ok", nil)
}

func TestRelayFailover(t *testing.T) {
	echo := startEcho(t)

	// 第一个上游端口确定无监听（先监听再关闭）
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	relay := startRelay(t, Config{
		Upstreams: []UpstreamConfig{
			{Address: deadAddr, Weight: 1},
			{Address: echo, Weight: 1},
		},
	})
	// 多轮连接都应落到健康上游
	for i := 0; i < 3; i++ {
		relayRoundtrip(t, relay, "failover-ok", nil)
	}
}

// TestRelayAllUpstreamsDead 验证全部上游失败时客户端连接被关闭。
func TestRelayAllUpstreamsDead(t *testing.T) {
	deads := make([]UpstreamConfig, 2)
	for i := range deads {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		deads[i] = UpstreamConfig{Address: ln.Addr().String(), Weight: 1}
		ln.Close()
	}
	relay := startRelay(t, Config{Upstreams: deads})

	conn, err := net.Dial("tcp", relay)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	// 连接被关闭：EOF（正常关）或 RST（Windows 上服务端未读
	// 待处理数据即关闭的表现），都不应读到数据
	if n, err := conn.Read(make([]byte, 4)); n != 0 || err == nil {
		t.Errorf("read = (%d, %v), want closed", n, err)
	}
}

// TestRelayListenTLS 验证监听端 TLS：客户端以 TLS 接入。
func TestRelayListenTLS(t *testing.T) {
	echo := startEcho(t)

	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "relay", true)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, srvCertPEM, 0o600)
	os.WriteFile(keyPath, srvKeyPEM, 0o600)

	relay := startRelay(t, Config{
		ListenTLS: &TLSSettings{Cert: certPath, Key: keyPath},
		Upstreams: []UpstreamConfig{{Address: echo, Weight: 1}},
	})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	relayRoundtrip(t, relay, "listen-tls-ok", &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
}

// TestRelayUpstreamTLS 验证上游端 TLS：中继以 TLS 客户端连上游。
func TestRelayUpstreamTLS(t *testing.T) {
	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "upstream", true)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// TLS echo 上游
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsUpLn := tls.NewListener(upLn, &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12})
	go func() {
		for {
			conn, err := tlsUpLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { tlsUpLn.Close() })

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caPath, caPEM, 0o600)

	relay := startRelay(t, Config{
		Upstreams: []UpstreamConfig{{
			Address: tlsUpLn.Addr().String(),
			Weight:  1,
			TLS:     &ClientTLSSettings{CA: caPath},
		}},
	})
	relayRoundtrip(t, relay, "upstream-tls-ok", nil)
}

// TestRelayBothMTLS 验证双向 mTLS：监听端校验客户端证书，上游端也
// 要求中继出示客户端证书。
func TestRelayBothMTLS(t *testing.T) {
	caPEM, ca, caKey := netutil.GenCA(t)

	// 监听端证书 + 校验客户端
	lsSrvPEM, lsSrvKeyPEM := netutil.GenLeaf(t, ca, caKey, "relay", true)
	clientCertPEM, clientKeyPEM := netutil.GenLeaf(t, ca, caKey, "relay-client", false)
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// 上游端：TLS + 要求客户端证书（即中继出示的 mTLS 证书）
	upSrvPEM, upSrvKeyPEM := netutil.GenLeaf(t, ca, caKey, "upstream", true)
	upCert, err := tls.X509KeyPair(upSrvPEM, upSrvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	relayCliPEM, relayCliKeyPEM := netutil.GenLeaf(t, ca, caKey, "relay-as-client", false)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mtlsUpLn := tls.NewListener(upLn, &tls.Config{
		Certificates: []tls.Certificate{upCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	go func() {
		for {
			conn, err := mtlsUpLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { mtlsUpLn.Close() })

	// 写中继配置：监听端 mTLS + 上游 mTLS
	dir := t.TempDir()
	lsCertPath := filepath.Join(dir, "ls-cert.pem")
	lsKeyPath := filepath.Join(dir, "ls-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	relayCliCertPath := filepath.Join(dir, "cli-cert.pem")
	relayCliKeyPath := filepath.Join(dir, "cli-key.pem")
	os.WriteFile(lsCertPath, lsSrvPEM, 0o600)
	os.WriteFile(lsKeyPath, lsSrvKeyPEM, 0o600)
	os.WriteFile(caPath, caPEM, 0o600)
	os.WriteFile(relayCliCertPath, relayCliPEM, 0o600)
	os.WriteFile(relayCliKeyPath, relayCliKeyPEM, 0o600)

	relay := startRelay(t, Config{
		ListenTLS: &TLSSettings{Cert: lsCertPath, Key: lsKeyPath, ClientCA: caPath},
		Upstreams: []UpstreamConfig{{
			Address: mtlsUpLn.Addr().String(),
			Weight:  1,
			TLS:     &ClientTLSSettings{CA: caPath, Cert: relayCliCertPath, Key: relayCliKeyPath},
		}},
	})

	// 客户端出示证书接入中继，端到端透传
	relayRoundtrip(t, relay, "both-mtls-ok", &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12,
	})
}

// startTaggedEcho 启动一个连上即写出单字节标识的服务并返回地址与标识。
func startTaggedEcho(t *testing.T, tag byte) string {
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
				conn.Write([]byte{tag})
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// TestRelayWeightDistribution 权重分布冒烟：两个上游 3:1，大量短连接
// 统计落点比例应接近 3:1（容差 ±15%）。
func TestRelayWeightDistribution(t *testing.T) {
	echoA := startTaggedEcho(t, 'A')
	echoB := startTaggedEcho(t, 'B')

	relay := startRelay(t, Config{
		Upstreams: []UpstreamConfig{
			{Address: echoA, Weight: 3},
			{Address: echoB, Weight: 1},
		},
	})

	const n = 4000
	hits := map[byte]int{}
	for i := 0; i < n; i++ {
		conn, err := net.Dial("tcp", relay)
		if err != nil {
			t.Fatal(err)
		}
		var tag [1]byte
		if _, err := io.ReadFull(conn, tag[:]); err != nil {
			t.Fatal(err)
		}
		hits[tag[0]]++
		conn.Close()
	}
	a, b := hits['A'], hits['B']
	if a+b != n {
		t.Fatalf("total = %d, want %d", a+b, n)
	}
	if a < int(0.75*n*0.85) || a > int(0.75*n*1.15) {
		t.Errorf("weight 3:1 distribution: A=%d B=%d (of %d), want ~%d/%d", a, b, n, n*3/4, n/4)
	}
}

// TestRelayClose 验证 Close 断开监听与活动连接，Serve 随之返回。
func TestRelayClose(t *testing.T) {
	echo := startEcho(t)

	r, err := New(&Config{
		Listen:    "127.0.0.1:0",
		Upstreams: []UpstreamConfig{{Address: echo, Weight: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- r.Serve(ln) }()

	// 建立一条长连接（echo 不会主动结束）
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}

	// Close：监听与活动连接都断开
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// 幂等
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	// 活动连接被断（读到错误/EOF）
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Errorf("active conn should be closed")
	}

	// Serve 返回 nil
	select {
	case err := <-serveDone:
		if err != nil {
			t.Errorf("serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("serve did not return after Close")
	}

	// 监听已关：新连接被拒
	if _, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		t.Errorf("new conn should be refused after Close")
	}
}
