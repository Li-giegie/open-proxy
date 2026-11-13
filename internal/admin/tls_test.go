package admin

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Li-giegie/open-proxy/internal/testutil"
)

// TestContentTLS 验证 TLS 字段以 PEM 内容（而非路径）配置：
// 监听端 TLS 直接生效，非法内容在创建期报 400。
func TestContentTLS(t *testing.T) {
	caPEM, ca, caKey := testutil.GenCA(t)
	srvCertPEM, srvKeyPEM := testutil.GenLeaf(t, ca, caKey, "resource-server", true)

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
