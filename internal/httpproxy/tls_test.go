package httpproxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Li-giegie/open-proxy/internal/netutil"
)

// newTLSServer 用 handler 启动一个自管 TLS 配置的 https 服务，返回其地址。
func newTLSServer(t *testing.T, tlsConf *tls.Config, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, TLSConfig: tlsConf}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })
	return "https://" + ln.Addr().String()
}

// TestChainUpstreamTLS 验证 https 上游：本地代理以 TLS 客户端连上游，
// 配置 UpstreamTLS.RootCAs 后链路可用；不配（不信任自签证书）则 502。
func TestChainUpstreamTLS(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tls-chain-ok"))
	}))
	defer target.Close()

	up, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	upSrv := httptest.NewUnstartedServer(up)
	upSrv.StartTLS()
	defer upSrv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(upSrv.Certificate())

	// 信任上游证书：成功
	local, err := New(Options{
		Upstream:    mustUpstreamURL(t, upSrv.URL),
		UpstreamTLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatal(err)
	}
	localSrv := httptest.NewServer(local)
	defer localSrv.Close()
	resp, err := proxyClient(t, localSrv.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("tls chain request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tls-chain-ok" {
		t.Errorf("body = %q, want %q", body, "tls-chain-ok")
	}

	// 不配 UpstreamTLS：系统根不信任自签证书 → 502
	local2, err := New(Options{Upstream: mustUpstreamURL(t, upSrv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	localSrv2 := httptest.NewServer(local2)
	defer localSrv2.Close()
	resp, err = proxyClient(t, localSrv2.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("untrusted chain request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("untrusted upstream: status = %d, want 502", resp.StatusCode)
	}
}

// TestChainUpstreamMTLS 验证与 https 上游的 mTLS：上游要求客户端证书，
// 本地代理经 UpstreamTLS.Certificates 出示证书后握手成功；不出示则失败。
func TestChainUpstreamMTLS(t *testing.T) {
	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "upstream-proxy", true)
	cliCertPEM, cliKeyPEM := netutil.GenLeaf(t, ca, caKey, "local-proxy", false)

	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, err := tls.X509KeyPair(cliCertPEM, cliKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	clientPool := x509.NewCertPool()
	clientPool.AppendCertsFromPEM(caPEM)

	up, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	upAddr := newTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    clientPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, up)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mtls-chain-ok"))
	}))
	defer target.Close()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// 出示客户端证书：握手成功
	local, err := New(Options{
		Upstream: mustUpstreamURL(t, upAddr),
		UpstreamTLS: &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{cliCert},
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	localSrv := httptest.NewServer(local)
	defer localSrv.Close()
	resp, err := proxyClient(t, localSrv.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("mtls chain request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "mtls-chain-ok" {
		t.Errorf("body = %q, want %q", body, "mtls-chain-ok")
	}

	// 不出示证书：上游握手拒绝 → 502
	local2, err := New(Options{
		Upstream:    mustUpstreamURL(t, upAddr),
		UpstreamTLS: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatal(err)
	}
	localSrv2 := httptest.NewServer(local2)
	defer localSrv2.Close()
	resp, err = proxyClient(t, localSrv2.URL).Get(target.URL + "/")
	if err != nil {
		t.Fatalf("no-cert chain request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("no client cert: status = %d, want 502", resp.StatusCode)
	}
}

// TestChainConnectTLSUpstream 验证 https 上游上的 CONNECT 隧道：
// 隧道建立（含对上游的 TLS 握手）后数据双向透传。
func TestChainConnectTLSUpstream(t *testing.T) {
	echoAddr := startEcho(t)

	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "upstream-proxy", true)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	up, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	upAddr := newTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS12,
	}, up)

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	local, err := New(Options{
		Upstream:    mustUpstreamURL(t, upAddr),
		UpstreamTLS: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
	})
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
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr.String(), echoAddr.String())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("hello"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("echo = %q, want %q", buf, "hello")
	}
}

// TestHTTP1OnlyALPN 验证声明仅 HTTP/1.1 后 TLS ALPN 只协商 http/1.1：
// 客户端即使提供 h2 也拿不到 h2（CONNECT 依赖 Hijack，h2 上无法工作）。
func TestHTTP1OnlyALPN(t *testing.T) {
	echoAddr := startEcho(t)

	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "forward-proxy", true)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   proxy,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
	}
	srv.Protocols = HTTP1OnlyProtocols()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	// 客户端同时提供 h2 与 http/1.1，ALPN 只应落到 http/1.1
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("ALPN 协商出 %q, want http/1.1", got)
	}

	// 协商出的连接上 CONNECT 正常工作
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr.String(), echoAddr.String())
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("alpn-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("alpn-ok"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "alpn-ok" {
		t.Errorf("echo = %q, want %q", buf, "alpn-ok")
	}
}
