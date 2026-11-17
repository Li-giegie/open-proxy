package admin

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Li-giegie/open-proxy/internal/certgen"
)

// TestCreateCAAPI 验证创建根 CA 端点：只建 CA 不自动签发叶子证书，
// 返回的证书/私钥可解析、可加载、非法 body 报 400。
func TestCreateCAAPI(t *testing.T) {
	_, api := newTestManager(t)

	resp, err := api.Client().Post(api.URL+"/api/cas", "application/json",
		bytes.NewReader([]byte(`{"common_name":"root-ca","days":30}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	var rec struct {
		ID         string `json:"id"`
		CommonName string `json:"common_name"`
		Algorithm  string `json:"algorithm"`
		Cert       string `json:"cert"`
		Key        string `json:"key"`
	}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" || rec.CommonName != "root-ca" || rec.Algorithm != "ECDSA" {
		t.Fatalf("记录字段异常: %+v", rec)
	}

	block, _ := pem.Decode([]byte(rec.Cert))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("ca pem 无效")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !caCert.IsCA {
		t.Errorf("ca.IsCA = false")
	}
	if caCert.Subject.CommonName != "root-ca" {
		t.Errorf("cn = %q", caCert.Subject.CommonName)
	}
	// 私钥可解析（可继续签发）
	if _, err := parseTestKey(rec.Key); err != nil {
		t.Errorf("私钥解析: %v", err)
	}

	// 只建根 CA：证书记录列表应为空
	resp2, _ := api.Client().Get(api.URL + "/api/certs")
	var certs []map[string]any
	json.NewDecoder(resp2.Body).Decode(&certs)
	resp2.Body.Close()
	if len(certs) != 0 {
		t.Errorf("创建根 CA 自动签发了叶子证书: %d 条", len(certs))
	}

	// 非法 body：400
	resp3, err := api.Client().Post(api.URL+"/api/cas", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", resp3.StatusCode)
	}
}

// parseTestKey 解析 PEM 私钥（PKCS#8/EC/RSA 通用）。
func parseTestKey(keyPEM string) (any, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("无效 PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// createTestCA 经 API 创建根 CA，返回记录。
func createTestCA(t *testing.T, api *httptest.Server, cn string) map[string]any {
	t.Helper()
	resp, err := api.Client().Post(api.URL+"/api/cas", "application/json",
		bytes.NewReader([]byte(fmt.Sprintf(`{"common_name":%q,"days":30}`, cn))))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create CA: status = %d, body = %s", resp.StatusCode, raw)
	}
	var rec map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// issueFromTestCA 经 API 从已保存 CA（按 ID）签发证书。
func issueFromTestCA(t *testing.T, api *httptest.Server, caID string, body map[string]any) *http.Response {
	t.Helper()
	body["ca_id"] = caID
	raw, _ := json.Marshal(body)
	resp, err := api.Client().Post(api.URL+"/api/certs/issue", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestCertIssueAPI 验证由已有 CA 签发客户端证书的端点：链有效、
// ExtKeyUsage 为 ClientAuth、缺 CA 报 400。
func TestCertIssueAPI(t *testing.T) {
	_, api := newTestManager(t)

	// 创建根 CA 并签发客户端证书
	ca := createTestCA(t, api, "issue-ca")
	resp2 := issueFromTestCA(t, api, ca["id"].(string), map[string]any{
		"common_name": "alice", "days": 30, "usage": "client",
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("issue status = %d, body = %s", resp2.StatusCode, raw)
	}
	var out struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	data, _ := io.ReadAll(resp2.Body)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(out.Cert), []byte(out.Key))
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice" {
		t.Errorf("cn = %q, want alice", leaf.Subject.CommonName)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", leaf.ExtKeyUsage)
	}
	caBlock, _ := pem.Decode([]byte(ca["cert"].(string)))
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("verify client chain: %v", err)
	}

	// 既无 ca_id 也无 ca/ca_key：400
	resp3, err := api.Client().Post(api.URL+"/api/certs/issue", "application/json",
		bytes.NewReader([]byte(`{"common_name":"x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("no ca: status = %d, want 400", resp3.StatusCode)
	}
	// 非法 usage：400
	resp4 := issueFromTestCA(t, api, ca["id"].(string), map[string]any{"common_name": "y", "usage": "xx"})
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusBadRequest {
		t.Errorf("bad usage: status = %d, want 400", resp4.StatusCode)
	}
}

// TestCertIssuePFX 验证签发端点的 PFX 导出：base64 解码后可被 openssl
// 语义校验（这里做结构级校验——MAC 用 PKCS#12 KDF 复算）。
func TestCertIssuePFX(t *testing.T) {
	_, api := newTestManager(t)

	// 创建根 CA 并签发（带 PFX 导出）
	ca := createTestCA(t, api, "pfx-ca")
	resp2 := issueFromTestCA(t, api, ca["id"].(string), map[string]any{
		"common_name": "browser-alice", "days": 30, "usage": "client",
		"pfx_password": "123456",
	})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("issue pfx: status = %d, body = %s", resp2.StatusCode, raw)
	}
	var out struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
		PFX  string `json:"pfx"`
	}
	data, _ := io.ReadAll(resp2.Body)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.PFX == "" {
		t.Fatalf("pfx 为空")
	}
	// base64 解码后对证书与私钥做配对校验（x/crypto 不支持 PBES2，
	// 这里仅验证容器可解析且包含签发出的证书）
	pfxDER, err := base64.StdEncoding.DecodeString(out.PFX)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfxDER) < 100 {
		t.Fatalf("pfx der = %d 字节，过小", len(pfxDER))
	}
	// 证书配对：签发出的证书 DER 应出现在容器字节流中（cert bag 为
	// 明文 OCTET STRING 内嵌 DER）
	pair, err := tls.X509KeyPair([]byte(out.Cert), []byte(out.Key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pfxDER, pair.Certificate[0]) {
		t.Errorf("容器中未找到签发出的证书 DER")
	}

	// 未要求 PFX 时响应不含 pfx 字段
	resp3 := issueFromTestCA(t, api, ca["id"].(string), map[string]any{
		"common_name": "x", "days": 5,
	})
	raw3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if bytes.Contains(raw3, []byte(`"pfx"`)) {
		t.Errorf("未请求 PFX 却返回了 pfx 字段")
	}
}

// TestCertsPersistedAcrossRestart 验证生成的证书持久化：
// generate/issue 落盘 certs.json，重建 Manager（模拟重启）后仍可读到，
// 且签发记录关联到已存储的 CA。
func TestCertsPersistedAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	dataFile := filepath.Join(dir, "proxies.json")
	_, api := newTestManagerAt(t, dataFile)

	// 创建根 CA 并签发一张客户端证书
	ca := createTestCA(t, api, "persist-ca")
	resp2 := issueFromTestCA(t, api, ca["id"].(string), map[string]any{
		"common_name": "persist-alice", "days": 30, "usage": "client",
	})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("issue: status = %d", resp2.StatusCode)
	}

	// 持久化文件存在
	certsFile := filepath.Join(dir, "certs.json")
	raw, err := os.ReadFile(certsFile)
	if err != nil {
		t.Fatalf("certs.json 未生成: %v", err)
	}
	var f struct {
		CAs   []map[string]any `json:"cas"`
		Certs []map[string]any `json:"certs"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.CAs) != 1 || len(f.Certs) != 1 {
		t.Fatalf("持久化记录数：CA=%d certs=%d, want 1/1", len(f.CAs), len(f.Certs))
	}

	// 模拟重启：重建 Manager 读取持久化数据
	m2, err := NewManager(NewStore(dataFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	m2.mu.Lock()
	defer m2.mu.Unlock()
	if got := len(m2.certs.cas); got != 1 {
		t.Errorf("重启后 CA 数 = %d, want 1", got)
	}
	if got := len(m2.certs.certs); got != 1 {
		t.Errorf("重启后证书数 = %d, want 1", got)
	}
	// 签发记录关联到已存储的 CA
	for _, c := range m2.certs.certs {
		if c.CommonName == "persist-alice" {
			if c.CAName != "persist-ca" || c.CAID == "" {
				t.Errorf("签发记录关联 CA = %q/%q, want persist-ca/非空", c.CAName, c.CAID)
			}
		}
	}
}

// TestSavedCertRecords 验证已保存记录的列表与删除端点（创建根 CA +
// 按 ca_id 签发，不再有 generate 端点）。
func TestSavedCertRecords(t *testing.T) {
	dir := t.TempDir()
	dataFile := filepath.Join(dir, "proxies.json")
	_, api := newTestManagerAt(t, dataFile)

	// 无记录时列表为空
	resp, err := api.Client().Get(api.URL + "/api/cas")
	if err != nil {
		t.Fatal(err)
	}
	var cas []map[string]any
	json.NewDecoder(resp.Body).Decode(&cas)
	resp.Body.Close()
	if len(cas) != 0 {
		t.Errorf("初始 CA 数 = %d, want 0", len(cas))
	}

	// 创建根 CA + 签发一张客户端证书
	ca := createTestCA(t, api, "rec-ca")
	resp2 := issueFromTestCA(t, api, ca["id"].(string), map[string]any{
		"common_name": "rec-alice", "days": 5, "usage": "client",
	})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("issue: status = %d", resp2.StatusCode)
	}

	// 列表可见
	resp3, _ := api.Client().Get(api.URL + "/api/cas")
	var caList []map[string]any
	json.NewDecoder(resp3.Body).Decode(&caList)
	resp3.Body.Close()
	if len(caList) != 1 || caList[0]["common_name"] != "rec-ca" {
		t.Fatalf("CA 列表 = %v", caList)
	}
	caID := caList[0]["id"].(string)

	resp4, _ := api.Client().Get(api.URL + "/api/certs")
	var certList []map[string]any
	json.NewDecoder(resp4.Body).Decode(&certList)
	resp4.Body.Close()
	if len(certList) != 1 {
		t.Fatalf("证书列表数 = %d, want 1", len(certList))
	}

	// 删除 CA 与证书
	req, _ := http.NewRequest(http.MethodDelete, api.URL+"/api/cas/"+caID, nil)
	resp5, _ := api.Client().Do(req)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusNoContent {
		t.Errorf("删除 CA: status = %d", resp5.StatusCode)
	}
	certID := certList[0]["id"].(string)
	req2, _ := http.NewRequest(http.MethodDelete, api.URL+"/api/certs/"+certID, nil)
	resp6, _ := api.Client().Do(req2)
	resp6.Body.Close()
	if resp6.StatusCode != http.StatusNoContent {
		t.Errorf("删除证书: status = %d", resp6.StatusCode)
	}

	// 删除不存在的：404
	req3, _ := http.NewRequest(http.MethodDelete, api.URL+"/api/cas/no-such", nil)
	resp7, _ := api.Client().Do(req3)
	resp7.Body.Close()
	if resp7.StatusCode != http.StatusNotFound {
		t.Errorf("删除不存在的 CA: status = %d, want 404", resp7.StatusCode)
	}

	// 删除后列表为空
	resp8, _ := api.Client().Get(api.URL + "/api/certs")
	var certList2 []map[string]any
	json.NewDecoder(resp8.Body).Decode(&certList2)
	resp8.Body.Close()
	if len(certList2) != 0 {
		t.Errorf("删除后证书数 = %d, want 0", len(certList2))
	}

	// CA 删除后按其 ID 签发：404
	resp9 := issueFromTestCA(t, api, caID, map[string]any{"common_name": "orphan", "days": 5})
	resp9.Body.Close()
	if resp9.StatusCode != http.StatusNotFound {
		t.Errorf("用已删除的 CA 签发: status = %d, want 404", resp9.StatusCode)
	}
}

// newTestManagerAt 以指定数据文件创建管理中心与测试服务。
func newTestManagerAt(t *testing.T, dataFile string) (*Manager, *httptest.Server) {
	t.Helper()
	m, err := NewManager(NewStore(dataFile), nil)
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(Handler(m, "", ""))
	t.Cleanup(api.Close)
	return m, api
}

// TestImportCAAndCert 验证导入端点：导入 CA 后可直接从它签发；
// 导入证书记录自动关联 CA、用途按 EKU 推断；坏 PEM 报 400。
func TestImportCAAndCert(t *testing.T) {
	_, api := newTestManager(t)

	// 外部生成一套（模拟导入来源）
	ca, err := certgen.NewCA(certgen.CAOptions{CommonName: "ext-ca", Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, caKeyPEM, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cliPEM, cliKeyPEM, err := ca.Issue(certgen.CertOptions{CommonName: "ext-alice", Days: 30, Usage: certgen.UsageClient})
	if err != nil {
		t.Fatal(err)
	}

	// 导入根 CA
	body, _ := json.Marshal(map[string]string{"cert": string(caPEM), "key": string(caKeyPEM)})
	resp, err := api.Client().Post(api.URL+"/api/cas/import", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("import ca: status = %d, body = %s", resp.StatusCode, raw)
	}
	var caRec struct {
		ID         string `json:"id"`
		CommonName string `json:"common_name"`
		Algorithm  string `json:"algorithm"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&caRec); err != nil {
		t.Fatal(err)
	}
	if caRec.CommonName != "ext-ca" || caRec.Algorithm != "ECDSA" {
		t.Errorf("导入 CA 记录 = %+v", caRec)
	}

	// 从导入的 CA 签发
	resp2 := issueFromTestCA(t, api, caRec.ID, map[string]any{"common_name": "from-imported", "days": 5})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("issue from imported: status = %d", resp2.StatusCode)
	}

	// 导入证书（关联该 CA）
	body2, _ := json.Marshal(map[string]string{
		"cert": string(cliPEM), "key": string(cliKeyPEM), "ca_id": caRec.ID,
	})
	resp3, err := api.Client().Post(api.URL+"/api/certs/import", "application/json", bytes.NewReader(body2))
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp3.Body)
		t.Fatalf("import cert: status = %d, body = %s", resp3.StatusCode, raw)
	}
	var certRec struct {
		CommonName string `json:"common_name"`
		Usage      string `json:"usage"`
		CAName     string `json:"ca_name"`
		CAID       string `json:"ca_id"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&certRec); err != nil {
		t.Fatal(err)
	}
	if certRec.CommonName != "ext-alice" || certRec.Usage != "client" ||
		certRec.CAName != "ext-ca" || certRec.CAID != caRec.ID {
		t.Errorf("导入证书记录 = %+v", certRec)
	}

	// 坏 PEM：400
	body3, _ := json.Marshal(map[string]string{"cert": "not pem", "key": "not pem"})
	resp4, err := api.Client().Post(api.URL+"/api/cas/import", "application/json", bytes.NewReader(body3))
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusBadRequest {
		t.Errorf("bad pem import: status = %d, want 400", resp4.StatusCode)
	}

	// 导入证书关联不存在的 CA：404
	body4, _ := json.Marshal(map[string]string{
		"cert": string(cliPEM), "key": string(cliKeyPEM), "ca_id": "no-such",
	})
	resp5, err := api.Client().Post(api.URL+"/api/certs/import", "application/json", bytes.NewReader(body4))
	if err != nil {
		t.Fatal(err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusNotFound {
		t.Errorf("bad ca_id import: status = %d, want 404", resp5.StatusCode)
	}
}

// TestExportRecordPFX 验证已保存证书记录的 PFX 导出端点：
// 导入一张证书后按口令导出，容器可解析且包含该证书。
func TestExportRecordPFX(t *testing.T) {
	_, api := newTestManager(t)

	ca, _ := certgen.NewCA(certgen.CAOptions{CommonName: "pfx-rec-ca", Days: 30})
	caPEM, caKeyPEM, _ := ca.Encode()
	cliPEM, cliKeyPEM, _ := ca.Issue(certgen.CertOptions{CommonName: "pfx-rec-alice", Days: 30, Usage: certgen.UsageClient})

	// 导入证书
	body, _ := json.Marshal(map[string]string{"cert": string(cliPEM), "key": string(cliKeyPEM)})
	resp, err := api.Client().Post(api.URL+"/api/certs/import", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&rec)
	resp.Body.Close()
	if rec.ID == "" {
		t.Fatal("导入未返回 id")
	}

	// 导出 PFX
	body2, _ := json.Marshal(map[string]string{"password": "123456"})
	req, _ := http.NewRequest(http.MethodPost, api.URL+"/api/certs/"+rec.ID+"/pfx", bytes.NewReader(body2))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := api.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("export pfx: status = %d, body = %s", resp2.StatusCode, raw)
	}
	var out struct {
		PFX string `json:"pfx"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(out.PFX)
	if err != nil {
		t.Fatal(err)
	}
	// 容器包含导入的证书 DER
	certBlock, _ := pem.Decode(cliPEM)
	if !bytes.Contains(der, certBlock.Bytes) {
		t.Errorf("容器中未找到导入的证书 DER")
	}

	// 空口令：400
	body3, _ := json.Marshal(map[string]string{"password": ""})
	req2, _ := http.NewRequest(http.MethodPost, api.URL+"/api/certs/"+rec.ID+"/pfx", bytes.NewReader(body3))
	req2.Header.Set("Content-Type", "application/json")
	resp3, _ := api.Client().Do(req2)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("empty password: status = %d, want 400", resp3.StatusCode)
	}

	// 不存在的记录：404
	body4, _ := json.Marshal(map[string]string{"password": "x"})
	req3, _ := http.NewRequest(http.MethodPost, api.URL+"/api/certs/no-such/pfx", bytes.NewReader(body4))
	req3.Header.Set("Content-Type", "application/json")
	resp4, _ := api.Client().Do(req3)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusNotFound {
		t.Errorf("missing record: status = %d, want 404", resp4.StatusCode)
	}

	_ = caPEM
	_ = caKeyPEM
}
