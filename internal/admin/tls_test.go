package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// genCA 生成自签 CA（测试用小 PKI，与 reverseproxy/httpproxy 的测试助手
// 同构，包私有不可复用故各自保留一份）。
func genCA(t *testing.T) (caPEM []byte, ca *x509.Certificate, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "admin-test-ca"},
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

// genLeaf 用 CA 签发叶子证书，server 为 true 时含 127.0.0.1 SAN。
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

// TestContentTLS 验证 TLS 字段以 PEM 内容（而非路径）配置：
// 监听端 TLS 直接生效，非法内容在创建期报 400。
func TestContentTLS(t *testing.T) {
	caPEM, ca, caKey := genCA(t)
	srvCertPEM, srvKeyPEM := genLeaf(t, ca, caKey, "resource-server", true)

	// 经代理访问的本地目标（确定性结果）
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content-tls-ok"))
	}))
	defer target.Close()

	_, api := newTestManager(t)

	// 用 PEM 内容创建带监听 TLS 的正向资源
	view := createResource(t, api, map[string]any{
		"name":    "内容TLS",
		"type":    TypeForward,
		"address": "127.0.0.1:0",
		"forward": map[string]any{
			"cert": string(srvCertPEM),
			"key":  string(srvKeyPEM),
		},
	})

	// 客户端信任该 CA 后经 https 代理访问目标
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(mustURL(t, "https://"+view.Address)),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	resp, err := client.Get(target.URL + "/")
	if err != nil {
		t.Fatalf("https 代理请求: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "content-tls-ok" {
		t.Errorf("resp = %d %q, want 200 content-tls-ok", resp.StatusCode, body)
	}

	// 非法 PEM 内容：创建期 400
	badPEM := []byte(`{"name":"坏证书","type":"forward","address":"127.0.0.1:0","forward":{"cert":"not-a-pem","key":"not-a-key"}}`)
	resp2, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(badPEM))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("bad pem: status = %d, want 400", resp2.StatusCode)
	}

	// cert 无 key：校验错误
	halfPEM := []byte(`{"name":"半证书","type":"forward","address":"127.0.0.1:0","forward":{"cert":"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"}}`)
	resp3, err := api.Client().Post(api.URL+"/api/resources", "application/json", bytes.NewReader(halfPEM))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("cert without key: status = %d, want 400", resp3.StatusCode)
	}
}
