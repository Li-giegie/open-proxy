package httpproxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	caPEM, ca, caKey := genCA(t)
	srvCertPEM, srvKeyPEM := genLeaf(t, ca, caKey, "upstream-proxy", true)
	cliCertPEM, cliKeyPEM := genLeaf(t, ca, caKey, "local-proxy", false)

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

	caPEM, ca, caKey := genCA(t)
	srvCertPEM, srvKeyPEM := genLeaf(t, ca, caKey, "upstream-proxy", true)
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
