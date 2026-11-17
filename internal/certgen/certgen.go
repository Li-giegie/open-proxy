// Package certgen 以**分步**的方式生成与签发内网/测试用证书，供管理
// 中心与 certgen 命令共用：
//
//	ca, _ := certgen.NewCA(certgen.CAOptions{...})   // 步骤一：创建 CA
//	caPEM, keyPEM, _ := ca.Encode()                  // 持久化 CA（证书 + 私钥）
//	ca, _ = certgen.LoadCA(caPEM, keyPEM)            //   或加载已有 CA
//	certPEM, keyPEM, _ := ca.Issue(certgen.CertOptions{...}) // 步骤二：签发叶子
//
// 两个步骤各自携带可选参数（主题、SAN、有效期、算法、曲线、用途），
// 零值字段均有默认值。支持的算法：ECDSA（P-256/P-384/P-521，默认）、
// RSA（默认 2048 位，可 3072/4096）、Ed25519；叶子证书跟随 CA 的算法
// 与参数。私钥统一以 PKCS#8 PEM 输出，读取兼容 EC SEC1 / RSA PKCS#1。
// 服务端形态的叶子证书 SAN 自动追加 localhost、127.0.0.1 与 ::1，
// 客户端形态以 CN 作为 mTLS 身份。
package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

const (
	defaultDays        = 3650       // 默认有效期：约 10 年（内网自用）
	defaultMaxSer      = 1 << 62    //
	validityWindow     = -time.Hour // 签发时间前移 1 小时，容忍时钟偏差
	caValidityHeadroom = 24 * time.Hour
	defaultRSABits     = 2048
)

// Algorithm 是签名算法。
type Algorithm string

const (
	// AlgoECDSA ECDSA（Curve 决定曲线，默认 P-256）。
	AlgoECDSA Algorithm = "ECDSA"
	// AlgoRSA RSA（RSABits 决定位数，默认 2048）。
	AlgoRSA Algorithm = "RSA"
	// AlgoEd25519 Ed25519。
	AlgoEd25519 Algorithm = "Ed25519"
)

// ParseAlgorithm 解析算法名称（大小写不敏感：ecdsa/rsa/ed25519，
// 空串为默认 ECDSA）。
func ParseAlgorithm(s string) (Algorithm, error) {
	switch lower(s) {
	case "", "ecdsa":
		return AlgoECDSA, nil
	case "rsa":
		return AlgoRSA, nil
	case "ed25519":
		return AlgoEd25519, nil
	default:
		return "", fmt.Errorf("未知算法 %q（ecdsa / rsa / ed25519）", s)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// ParseCurve 解析 ECDSA 曲线名称（P-256 / P-384 / P-521）。
func ParseCurve(name string) (elliptic.Curve, error) {
	switch lower(name) {
	case "", "p-256", "p256":
		return elliptic.P256(), nil
	case "p-384", "p384":
		return elliptic.P384(), nil
	case "p-521", "p521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("未知曲线 %q（P-256 / P-384 / P-521）", name)
	}
}

// Usage 是叶子证书的用途，决定 ExtKeyUsage 与 SAN 策略。
type Usage int

const (
	// UsageServer 服务端证书：ExtKeyUsage 含 ServerAuth（外加 ClientAuth），
	// SAN 覆盖 CommonName 与附加 SAN 外加 localhost、127.0.0.1、::1。
	UsageServer Usage = iota
	// UsageClient 客户端证书：ExtKeyUsage 仅 ClientAuth，CN 即 mTLS 身份，无 SAN。
	UsageClient
	// UsageBoth 双向通用：ExtKeyUsage 含 ServerAuth 与 ClientAuth，SAN 同服务端。
	UsageBoth
)

func (u Usage) String() string {
	switch u {
	case UsageClient:
		return "client"
	case UsageBoth:
		return "both"
	default:
		return "server"
	}
}

// ParseUsage 解析用途字符串（server/client/both）。
func ParseUsage(s string) (Usage, error) {
	switch lower(s) {
	case "", "server":
		return UsageServer, nil
	case "client":
		return UsageClient, nil
	case "both":
		return UsageBoth, nil
	default:
		return 0, fmt.Errorf("未知用途 %q（server / client / both）", s)
	}
}

// CAOptions 是创建自签 CA 的可选项，零值字段用默认值。
type CAOptions struct {
	CommonName   string         // 默认 "open-proxy-ca"
	Organization []string       // 主题 O 字段
	Days         int            // 有效期天数，默认 3650
	Algorithm    Algorithm      // 签名算法，默认 ECDSA
	Curve        elliptic.Curve // ECDSA 曲线，默认 P-256
	RSABits      int            // RSA 位数，默认 2048
}

// CertOptions 是签发叶子证书的可选项，零值字段用默认值。叶子密钥的
// 算法与参数跟随 CA，这里只控制证书内容。
type CertOptions struct {
	CommonName   string   // 默认 "open-proxy"
	Organization []string // 主题 O 字段
	DNSNames     []string // 附加 DNS SAN（服务端形态，与 CommonName/localhost 合并）
	IPs          []string // 附加 IP SAN（文本形式，如 "10.0.0.5"、"fd00::1"）
	Days         int      // 有效期天数，默认 3650
	Usage        Usage    // 默认 UsageServer
}

// CA 是内存中的证书颁发机构：证书 + 签名私钥（crypto.Signer）。
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// NewCA 创建自签 CA（步骤一：全新 CA）。
func NewCA(opts CAOptions) (*CA, error) {
	if opts.CommonName == "" {
		opts.CommonName = "open-proxy-ca"
	}
	if opts.Days <= 0 {
		opts.Days = defaultDays
	}
	if opts.Algorithm == "" {
		opts.Algorithm = AlgoECDSA
	}

	key, err := genKey(opts.Algorithm, opts.Curve, opts.RSABits)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               subject(opts.CommonName, opts.Organization),
		NotBefore:             now.Add(validityWindow),
		NotAfter:              now.Add(time.Duration(opts.Days)*24*time.Hour + caValidityHeadroom),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("签发 CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("解析 CA: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

// LoadCA 加载已有 CA（步骤一的另一种来源：PEM 证书 + 私钥）。
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("CA 证书不是合法的 PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 证书: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("提供的证书不是 CA（IsCA = false）")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析 CA 私钥: %w", err)
	}
	return &CA{cert: cert, key: key}, nil
}

// Encode 返回 CA 的证书与私钥 PEM（持久化用；持有私钥即可继续签发）。
func (c *CA) Encode() (certPEM, keyPEM []byte, err error) {
	keyPEM, err = marshalKey(c.key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}), keyPEM, nil
}

// Subject 返回 CA 主题（预览/展示用）。
func (c *CA) Subject() string { return c.cert.Subject.String() }

// NotAfter 返回 CA 过期时间。
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Algorithm 返回 CA 的签名算法。
func (c *CA) Algorithm() Algorithm {
	switch c.key.Public().(type) {
	case *rsa.PublicKey:
		return AlgoRSA
	case ed25519.PublicKey:
		return AlgoEd25519
	default:
		return AlgoECDSA
	}
}

// Issue 用 CA 签发一张叶子证书（步骤二），返回证书与私钥 PEM。
// 叶子密钥与 CA 同算法同参数。
func (c *CA) Issue(opts CertOptions) (certPEM, keyPEM []byte, err error) {
	if opts.CommonName == "" {
		opts.CommonName = "open-proxy"
	}
	if opts.Days <= 0 {
		opts.Days = defaultDays
	}

	key, err := c.leafKey() // 叶子密钥与 CA 同算法同参数
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      subject(opts.CommonName, opts.Organization),
		NotBefore:    time.Now().Add(validityWindow),
		NotAfter:     time.Now().Add(time.Duration(opts.Days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	// 用途决定 ExtKeyUsage 与 SAN 策略：客户端形态仅 ClientAuth、无 SAN；
	// 服务端/双向形态含 ServerAuth+ClientAuth 并填充 SAN
	switch opts.Usage {
	case UsageClient:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		if err := setSAN(tmpl, opts); err != nil {
			return nil, nil, err
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("签发证书: %w", err)
	}
	keyPEM, err = marshalKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

// genKey 按算法生成私钥。curve/bits 仅在 ECDSA/RSA 时生效；传入
// nil/0 时按 CA 密钥的参数推导（同曲线/同位数）。
func genKey(algo Algorithm, curve elliptic.Curve, bits int) (crypto.Signer, error) {
	switch algo {
	case AlgoRSA:
		if bits <= 0 {
			bits = defaultRSABits
		}
		if bits < 2048 {
			return nil, fmt.Errorf("RSA 位数 %d 过小（至少 2048）", bits)
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("生成 RSA 私钥: %w", err)
		}
		return key, nil
	case AlgoEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成 Ed25519 私钥: %w", err)
		}
		return key, nil
	default: // AlgoECDSA
		if curve == nil {
			curve = elliptic.P256()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成 ECDSA 私钥: %w", err)
		}
		return key, nil
	}
}

// leafKey 生成与 CA 同算法同参数的叶子私钥（ECDSA 同曲线、RSA 同位数）。
func (c *CA) leafKey() (crypto.Signer, error) {
	switch pub := c.key.Public().(type) {
	case *ecdsa.PublicKey:
		key, err := ecdsa.GenerateKey(pub.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成 ECDSA 私钥: %w", err)
		}
		return key, nil
	case *rsa.PublicKey:
		key, err := rsa.GenerateKey(rand.Reader, pub.N.BitLen())
		if err != nil {
			return nil, fmt.Errorf("生成 RSA 私钥: %w", err)
		}
		return key, nil
	case ed25519.PublicKey:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成 Ed25519 私钥: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("CA 私钥类型 %T 不支持签发", c.key)
	}
}
func setSAN(tmpl *x509.Certificate, opts CertOptions) error {
	tmpl.DNSNames = append([]string{"localhost"}, opts.DNSNames...)
	tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, s := range opts.IPs {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("无效的 IP SAN %q", s)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	if ip := net.ParseIP(opts.CommonName); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else if opts.CommonName != "localhost" {
		tmpl.DNSNames = append(tmpl.DNSNames, opts.CommonName)
	}
	return nil
}

// subject 组装主题（CN + 可选 O）。
func subject(cn string, org []string) pkix.Name {
	name := pkix.Name{CommonName: cn}
	if len(org) > 0 {
		name.Organization = org
	}
	return name
}

// marshalKey 把私钥编码为 PKCS#8 PEM（ECDSA/RSA/Ed25519 通用）。
func marshalKey(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("编码私钥: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parseKey 解析私钥（PKCS#8 通用，兼容 EC SEC1 与 RSA PKCS#1），
// 返回可作为 crypto.Signer 使用的私钥。
func parseKey(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("不是合法的 PEM")
	}
	// 统一优先 PKCS#8（覆盖 ECDSA/RSA/Ed25519）
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("私钥类型 %T 不支持签名", key)
	}
	// 兼容历史产出的 EC SEC1
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	// 兼容 RSA PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("不支持的私钥格式（需要 PKCS#8 / EC / RSA）")
}

// randomSerial 生成正的随机序列号（无符号、不越 int64）。
func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, big.NewInt(defaultMaxSer))
	if err != nil {
		// 随机源失败时退化为时间戳，保证可签发
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}
