package proxycfg_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Li-giegie/open-proxy/internal/proxycfg"
	"github.com/Li-giegie/open-proxy/internal/testutil"
)

// testPKI 生成一套测试 PKI（基于 testutil，写到临时文件以测试路径版
// 入口）：根 CA、服务端证书（127.0.0.1）、客户端证书。
type testPKI struct {
	caPath     string
	caPEM      []byte
	serverPath string
	serverKey  string
	clientCert tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caPEM, ca, caKey := testutil.GenCA(t)
	serverPEM, serverKeyPEM := testutil.GenLeaf(t, ca, caKey, "open-proxy-test", true)
	clientPEM, clientKeyPEM := testutil.GenLeaf(t, ca, caKey, "open-proxy-test", false)
	clientCert, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	return &testPKI{
		caPath:     writePEMFile(t, filepath.Join(dir, "ca.pem"), caPEM),
		caPEM:      caPEM,
		serverPath: writePEMFile(t, filepath.Join(dir, "cert.pem"), serverPEM),
		serverKey:  writePEMFile(t, filepath.Join(dir, "key.pem"), serverKeyPEM),
		clientCert: clientCert,
	}
}

// writePEMFile 把 PEM 内容写到文件并返回路径，供路径版入口测试。
func writePEMFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerTLSValidation(t *testing.T) {
	// 全空：明文监听
	conf, err := proxycfg.ServerTLS("", "", "")
	if err != nil || conf != nil {
		t.Errorf("empty args: conf=%v err=%v, want nil/nil", conf, err)
	}
	// 缺 --key
	if _, err := proxycfg.ServerTLS("cert.pem", "", ""); err == nil {
		t.Errorf("missing key: want error")
	}
	// 只有 --client-ca
	if _, err := proxycfg.ServerTLS("", "", "ca.pem"); err == nil {
		t.Errorf("client-ca alone: want error")
	}
	// 文件不存在
	if _, err := proxycfg.ServerTLS("no.pem", "no.pem", ""); err == nil {
		t.Errorf("missing files: want error")
	}
}

// TestMTLSListener 端到端验证：mTLS 监听器只放行持有效客户端证书的连接。
func TestMTLSListener(t *testing.T) {
	pki := newTestPKI(t)

	tlsConf, err := proxycfg.ServerTLS(pki.serverPath, pki.serverKey, pki.caPath)
	if err != nil {
		t.Fatalf("proxycfg.ServerTLS: %v", err)
	}
	if tlsConf.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsConf.ClientAuth)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		TLSConfig: tlsConf,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(pki.caPEM)
	addr := "https://" + ln.Addr().String() + "/"

	// 带客户端证书：握手成功
	withCert := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool, Certificates: []tls.Certificate{pki.clientCert}},
	}, Timeout: 5 * time.Second}
	resp, err := withCert.Get(addr)
	if err != nil {
		t.Fatalf("with client cert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("with client cert: status = %d", resp.StatusCode)
	}

	// 不带客户端证书：握手被拒
	noCert := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}, Timeout: 5 * time.Second}
	if _, err := noCert.Get(addr); err == nil {
		t.Errorf("without client cert: connection should be rejected")
	}
}

// TestTLSListener 验证普通 TLS（不校验客户端证书）。
func TestTLSListener(t *testing.T) {
	pki := newTestPKI(t)

	tlsConf, err := proxycfg.ServerTLS(pki.serverPath, pki.serverKey, "")
	if err != nil {
		t.Fatalf("proxycfg.ServerTLS: %v", err)
	}
	if tlsConf.ClientCAs != nil {
		t.Errorf("plain TLS should not verify client certs")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		TLSConfig: tlsConf,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(pki.caPEM)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("tls request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
