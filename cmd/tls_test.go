package cmd

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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// issueCert 用 parent 签发一张证书。parent 传 nil 表示自签（根 CA）。
// 返回 tls 证书对象与 PEM 编码的证书、私钥文件路径。
func issueCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey,
	tmpl *x509.Certificate) (tls.Certificate, string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return cert, certPath, keyPath
}

func baseTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "open-proxy-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// writeCAMem 把 CA 证书写到文件，返回文件路径与 PEM 内容。
func writeCAMem(t *testing.T, ca tls.Certificate) (string, []byte) {
	t.Helper()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, caPEM
}

// testPKI 生成一套测试 PKI：根 CA、服务端证书（127.0.0.1）、客户端证书。
type testPKI struct {
	ca         tls.Certificate
	caPath     string
	caPEM      []byte
	serverPath string
	serverKey  string
	clientCert tls.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caTmpl := baseTemplate(t)
	caTmpl.IsCA = true
	caTmpl.BasicConstraintsValid = true // 不设置则不会写入 basicConstraints 扩展，无法作为签发者
	caTmpl.KeyUsage = x509.KeyUsageCertSign
	ca, _, _ := issueCert(t, nil, nil, caTmpl)
	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caKey := ca.PrivateKey.(*ecdsa.PrivateKey)

	serverTmpl := baseTemplate(t)
	serverTmpl.DNSNames = []string{"localhost"}
	serverTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	serverTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	_, serverPath, serverKey := issueCert(t, caLeaf, caKey, serverTmpl)

	clientTmpl := baseTemplate(t)
	clientTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	clientCert, _, _ := issueCert(t, caLeaf, caKey, clientTmpl)

	caPath, caPEM := writeCAMem(t, ca)
	return &testPKI{ca: ca, caPath: caPath, caPEM: caPEM, serverPath: serverPath, serverKey: serverKey, clientCert: clientCert}
}

func TestNewTLSConfigValidation(t *testing.T) {
	// 全空：明文监听
	conf, err := newTLSConfig("", "", "")
	if err != nil || conf != nil {
		t.Errorf("empty args: conf=%v err=%v, want nil/nil", conf, err)
	}
	// 缺 --key
	if _, err := newTLSConfig("cert.pem", "", ""); err == nil {
		t.Errorf("missing key: want error")
	}
	// 只有 --client-ca
	if _, err := newTLSConfig("", "", "ca.pem"); err == nil {
		t.Errorf("client-ca alone: want error")
	}
	// 文件不存在
	if _, err := newTLSConfig("no.pem", "no.pem", ""); err == nil {
		t.Errorf("missing files: want error")
	}
}

// TestMTLSListener 端到端验证：mTLS 监听器只放行持有效客户端证书的连接。
func TestMTLSListener(t *testing.T) {
	pki := newTestPKI(t)

	tlsConf, err := newTLSConfig(pki.serverPath, pki.serverKey, pki.caPath)
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
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

	tlsConf, err := newTLSConfig(pki.serverPath, pki.serverKey, "")
	if err != nil {
		t.Fatalf("newTLSConfig: %v", err)
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
