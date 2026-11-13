package reverseproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// genCA 生成自签 CA，返回 PEM 与解析后的证书/私钥。
func genCA(t *testing.T) (caPEM []byte, ca *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca, key
}

// genLeaf 用 CA 签发叶子证书。server 为 true 时用于 TLS 服务端（含 127.0.0.1
// SAN），否则作为客户端证书（mTLS 出示）。
func genLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

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
	caPEM, ca, caKey := genCA(t)
	srvCertPEM, srvKeyPEM := genLeaf(t, ca, caKey, "backend", true)
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
	_, ca, caKey := genCA(t)
	srvCertPEM, srvKeyPEM := genLeaf(t, ca, caKey, "backend", true)
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
	caPEM, ca, caKey := genCA(t)
	srvCertPEM, srvKeyPEM := genLeaf(t, ca, caKey, "backend", true)
	cliCertPEM, cliKeyPEM := genLeaf(t, ca, caKey, "proxy-client", false)

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
