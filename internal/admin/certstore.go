package admin

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Li-giegie/open-proxy/internal/certgen"
)

// CARecord 是管理中心持久化的一台证书颁发机构：证书 + 私钥。
// 持有私钥即可继续签发叶子证书（步骤二）。
type CARecord struct {
	ID         string    `json:"id"`
	CommonName string    `json:"common_name"`
	Algorithm  string    `json:"algorithm"`
	CreatedAt  time.Time `json:"created_at"`
	NotAfter   time.Time `json:"not_after"`
	CertPEM    string    `json:"cert"`
	KeyPEM     string    `json:"key"`
}

// CertRecord 是由某台 CA 签发出的叶子证书（步骤二的产物）。
type CertRecord struct {
	ID         string    `json:"id"`
	CAID       string    `json:"ca_id"`
	CAName     string    `json:"ca_name"` // 签发 CA 的 CN（CA 删除后仍可显示）
	CommonName string    `json:"common_name"`
	Usage      string    `json:"usage"`
	CreatedAt  time.Time `json:"created_at"`
	NotAfter   time.Time `json:"not_after"`
	CertPEM    string    `json:"cert"`
	KeyPEM     string    `json:"key"`
}

// CertStore 把 CA 与已签发证书持久化为 JSON 文件（临时文件 + 原子替换）。
// path 为空表示仅内存（不持久化）。
type CertStore struct {
	path string
}

// NewCertStore 创建指向 path 的证书存储。
func NewCertStore(path string) *CertStore {
	return &CertStore{path: path}
}

// certFile 是持久化文件的顶层结构。
type certFile struct {
	CAs   []*CARecord   `json:"cas"`
	Certs []*CertRecord `json:"certs"`
}

// certState 是证书模块的内存状态（挂靠 Manager，锁复用 Manager.mu）。
type certState struct {
	store *CertStore
	cas   map[string]*CARecord
	certs map[string]*CertRecord
}

// loadCertState 读取持久化的证书数据（文件不存在时为空）。
func loadCertState(store *CertStore) (*certState, error) {
	st := &certState{
		store: store,
		cas:   map[string]*CARecord{},
		certs: map[string]*CertRecord{},
	}
	if store.path == "" {
		return st, nil
	}
	data, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", store.path, err)
	}
	var f certFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", store.path, err)
	}
	for _, ca := range f.CAs {
		st.cas[ca.ID] = ca
	}
	for _, c := range f.Certs {
		st.certs[c.ID] = c
	}
	return st, nil
}

// saveLocked 持久化证书数据（调用方需持 Manager.mu）。
func (s *certState) saveLocked() error {
	if s.store.path == "" {
		return nil
	}
	f := certFile{
		CAs:   make([]*CARecord, 0, len(s.cas)),
		Certs: make([]*CertRecord, 0, len(s.certs)),
	}
	for _, ca := range s.cas {
		f.CAs = append(f.CAs, ca)
	}
	for _, c := range s.certs {
		f.Certs = append(f.Certs, c)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化证书: %w", err)
	}
	tmp := s.store.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.store.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换 %s: %w", s.store.path, err)
	}
	return nil
}

// createCA 创建并持久化一台 CA（步骤一）。
// ID 由调用方生成；返回记录的同时校验证书可解析（取 NotAfter）。
func (s *certState) createCA(id string, ca *certgen.CA, algorithm string, cn string) (*CARecord, error) {
	certPEM, keyPEM, err := ca.Encode()
	if err != nil {
		return nil, err
	}
	rec := &CARecord{
		ID:         id,
		CommonName: cn,
		Algorithm:  algorithm,
		CreatedAt:  time.Now(),
		NotAfter:   ca.NotAfter(),
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
	}
	s.cas[id] = rec
	if err := s.saveLocked(); err != nil {
		delete(s.cas, id)
		return nil, err
	}
	return rec, nil
}

// saveCert 记录一张已签发出的叶子证书（PEM 由调用方给出——不重新签发，
// 保证记录与返回给调用方的证书是同一张）并持久化。
// caPEM 用于关联已存储的 CA（找不到对应记录时仅记录 CA 名称）。
func (s *certState) saveCert(id, caPEM string, certPEM, keyPEM []byte, opts certgen.CertOptions) (*CertRecord, error) {
	cert, err := parseStoredCert(string(certPEM))
	if err != nil {
		return nil, err
	}
	rec := &CertRecord{
		ID:         id,
		CommonName: opts.CommonName,
		Usage:      opts.Usage.String(),
		CreatedAt:  time.Now(),
		NotAfter:   cert.NotAfter,
		CertPEM:    string(certPEM),
		KeyPEM:     string(keyPEM),
	}
	// 关联签发 CA：按证书内容匹配已存储的记录
	for _, ca := range s.cas {
		if ca.CertPEM == caPEM {
			rec.CAID, rec.CAName = ca.ID, ca.CommonName
			break
		}
	}
	if rec.CAName == "" {
		if caCert, err := parseStoredCert(caPEM); err == nil {
			rec.CAName = caCert.Subject.CommonName
		}
	}
	s.certs[id] = rec
	if err := s.saveLocked(); err != nil {
		delete(s.certs, id)
		return nil, err
	}
	return rec, nil
}

// deleteCA 删除 CA（保留由它签发的证书记录，记录里存有 CA 名称可溯）。
func (s *certState) deleteCA(id string) bool {
	if _, ok := s.cas[id]; !ok {
		return false
	}
	delete(s.cas, id)
	return true
}

// deleteCert 删除一张已签发的证书记录。
func (s *certState) deleteCert(id string) bool {
	if _, ok := s.certs[id]; !ok {
		return false
	}
	delete(s.certs, id)
	return true
}

// listCAs / listCerts 返回全部记录（按创建时间从新到旧）。
func (s *certState) listCAs() []*CARecord {
	out := make([]*CARecord, 0, len(s.cas))
	for _, ca := range s.cas {
		out = append(out, ca)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *certState) listCerts() []*CertRecord {
	out := make([]*CertRecord, 0, len(s.certs))
	for _, c := range s.certs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// parseStoredCert 解析记录里的证书 PEM（用于取过期时间等）。
func parseStoredCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("证书记录的 PEM 无效")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certStoreDefaultPath 由资源存储路径推导证书存储路径
// （proxies.json → certs.json，同目录）。
func certStoreDefaultPath(dataPath string) string {
	if dataPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dataPath), "certs.json")
}

// importCA 从 PEM 导入已有 CA（证书 + 私钥）并持久化。
// 名称/算法/有效期从证书解析。
func (s *certState) importCA(id string, certPEM, keyPEM string) (*CARecord, error) {
	if _, err := certgen.LoadCA([]byte(certPEM), []byte(keyPEM)); err != nil {
		return nil, err
	}
	cert, err := parseStoredCert(certPEM)
	if err != nil {
		return nil, err
	}
	rec := &CARecord{
		ID:         id,
		CommonName: cert.Subject.CommonName,
		Algorithm:  algorithmOf(cert),
		CreatedAt:  time.Now(),
		NotAfter:   cert.NotAfter,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
	}
	s.cas[id] = rec
	if err := s.saveLocked(); err != nil {
		delete(s.cas, id)
		return nil, err
	}
	return rec, nil
}

// importCert 从 PEM 导入一张已签发的证书（证书 + 私钥）并持久化。
// 用途按 ExtKeyUsage 推断；ca_id 给出时关联已存储的 CA，
// 否则以证书的签发者 CN 作为来源记录。
func (s *certState) importCert(id string, certPEM, keyPEM, caID string) (*CertRecord, error) {
	// 私钥须可解析（PKCS#8 / EC SEC1 / RSA PKCS#1）且与证书配对
	key, err := certgen.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("解析私钥: %w", err)
	}
	cert, err := parseStoredCert(certPEM)
	if err != nil {
		return nil, err
	}
	if !equalPublicKeys(key.Public(), cert.PublicKey) {
		return nil, errors.New("私钥与证书不配对或格式不支持")
	}
	rec := &CertRecord{
		ID:         id,
		CommonName: cert.Subject.CommonName,
		Usage:      usageOf(cert),
		CreatedAt:  time.Now(),
		NotAfter:   cert.NotAfter,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
	}
	if caID != "" {
		if ca, ok := s.cas[caID]; ok {
			rec.CAID, rec.CAName = ca.ID, ca.CommonName
		} else {
			return nil, fmt.Errorf("CA 记录 %s 不存在", caID)
		}
	} else {
		rec.CAName = cert.Issuer.CommonName // 来源 CA 的 CN（溯源展示用）
	}
	s.certs[id] = rec
	if err := s.saveLocked(); err != nil {
		delete(s.certs, id)
		return nil, err
	}
	return rec, nil
}

// algorithmOf 由公钥类型推断签名算法名。
func algorithmOf(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "ECDSA"
	}
}

// usageOf 由 ExtKeyUsage 推断用途（both/匹配 UI 文案 server/client/both）。
func usageOf(cert *x509.Certificate) string {
	server, client := false, false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			server = true
		}
		if u == x509.ExtKeyUsageClientAuth {
			client = true
		}
	}
	switch {
	case server && client:
		return "both"
	case client:
		return "client"
	case server:
		return "server"
	default:
		return "client" // 无 EKU 时按客户端最小授权理解
	}
}

// equalPublicKeys 比较两个公钥是否一致（校验私钥与证书配对）。
func equalPublicKeys(a, b any) bool {
	ab, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && bytes.Equal(ab, bb)
}
