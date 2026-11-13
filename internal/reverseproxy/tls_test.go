package reverseproxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Li-giegie/open-proxy/internal/testutil"
)

// newTLSBackend 启动一个带自定义 TLS 配置的测试 backend。
func newTLSBackend(t *testing.T, tlsConf *tls.Config, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsConf
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestBackendTLS 验证出站客户端信任自定义 CA：自签证书的 https backend
// 在配置 CAPEM 后可正常转发。
func TestBackendTLS(t *testing.T) {
	caPEM, ca, caKey := testutil.GenCA(t)
	srvCertPEM, srvKeyPEM := testutil.GenLeaf(t, ca, caKey, "backend", true)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	backend := newTLSBackend(t, &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tls-ok")) })

	handler, err := New([]string{backend.URL}, WithBackendTLS(BackendTLSConfig{CAPEM: caPEM}))
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestBackendTLSUntrusted 验证默认不信任自签证书：不配 CA 时转发失败 502。
func TestBackendTLSUntrusted(t *testing.T) {
	_, ca, caKey := testutil.GenCA(t)
	srvCertPEM, srvKeyPEM := testutil.GenLeaf(t, ca, caKey, "backend", true)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	backend := newTLSBackend(t, &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12},
		func(w http.ResponseWriter, r *http.Request) {})

	handler, err := New([]string{backend.URL}) // 无 WithBackendTLS，用系统根证书
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502（自签证书不应被默认信任）", resp.StatusCode)
	}
}

// TestBackendMTLS 验证出站 mTLS：backend 要求并校验客户端证书，
// 反向代理通过 CertPEM/KeyPEM 出示证书后握手成功。
func TestBackendMTLS(t *testing.T) {
	caPEM, ca, caKey := testutil.GenCA(t)
	srvCertPEM, srvKeyPEM := testutil.GenLeaf(t, ca, caKey, "backend", true)
	cliCertPEM, cliKeyPEM := testutil.GenLeaf(t, ca, caKey, "proxy-client", false)

	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(ca)

	var peerCN string
	backend := newTLSBackend(t, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    clientPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		w.Write([]byte("mtls-ok"))
	})

	handler, err := New([]string{backend.URL}, WithBackendTLS(BackendTLSConfig{
		CAPEM:   caPEM,
		CertPEM: cliCertPEM,
		KeyPEM:  cliKeyPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200（mTLS 握手应成功）", resp.StatusCode)
	}
	if peerCN != "proxy-client" {
		t.Errorf("backend 看到的客户端证书 CN = %q, want %q", peerCN, "proxy-client")
	}
}

func TestBackendTLSValidation(t *testing.T) {
	// cert 与 key 必须同时设置
	if _, err := New([]string{"http://127.0.0.1:1"}, WithBackendTLS(BackendTLSConfig{CertPEM: []byte("a")})); err == nil {
		t.Errorf("只有 CertPEM: want error")
	}
	if _, err := New([]string{"http://127.0.0.1:1"}, WithBackendTLS(BackendTLSConfig{KeyPEM: []byte("b")})); err == nil {
		t.Errorf("只有 KeyPEM: want error")
	}
	// CA 内容不是合法 PEM
	if _, err := New([]string{"http://127.0.0.1:1"}, WithBackendTLS(BackendTLSConfig{CAPEM: []byte("not-a-pem")})); err == nil {
		t.Errorf("非法 CA: want error")
	}
	// 证书内容不配套
	if _, err := New([]string{"http://127.0.0.1:1"}, WithBackendTLS(BackendTLSConfig{
		CertPEM: []byte("-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n"),
		KeyPEM:  []byte("-----BEGIN CERTIFICATE-----\nbm90LWEta2V5\n-----END CERTIFICATE-----\n"),
	})); err == nil {
		t.Errorf("非法证书对: want error")
	}
}
