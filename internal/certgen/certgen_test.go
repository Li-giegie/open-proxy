package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// mustCert 解析 PEM 证书。
func mustCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("invalid cert pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustKey(t *testing.T, pemBytes []byte) crypto.Signer {
	t.Helper()
	key, err := parseKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newTestCA 建一个默认 CA 并返回其 PEM 编码。
func newTestCA(t *testing.T) (*CA, []byte, []byte) {
	t.Helper()
	ca, err := NewCA(CAOptions{Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return ca, certPEM, keyPEM
}

func TestNewCAAndEncode(t *testing.T) {
	_, certPEM, keyPEM := newTestCA(t)

	cert := mustCert(t, certPEM)
	if !cert.IsCA {
		t.Errorf("IsCA = false")
	}
	if cert.Subject.CommonName != "open-proxy-ca" {
		t.Errorf("cn = %q", cert.Subject.CommonName)
	}
	if !cert.NotAfter.After(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("NotAfter = %v，应接近 30 天", cert.NotAfter)
	}
	if mustKey(t, keyPEM) == nil {
		t.Fatal("key nil")
	}
}

// TestNewCAOptions 验证可选项：CN、组织、曲线。
func TestNewCAOptions(t *testing.T) {
	ca, err := NewCA(CAOptions{
		CommonName:   "custom-ca",
		Organization: []string{"Acme"},
		Days:         90,
		Curve:        mustCurve(t, "P-384"),
	})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cert := mustCert(t, certPEM)
	if cert.Subject.CommonName != "custom-ca" {
		t.Errorf("cn = %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Acme" {
		t.Errorf("org = %v", cert.Subject.Organization)
	}
	if got, ok := mustKey(t, keyPEM).(*ecdsa.PrivateKey); !ok || got.Curve != mustCurve(t, "P-384") {
		t.Errorf("curve 不匹配，want P-384")
	}
}

// TestNewCAAlgorithm 覆盖 RSA 与 Ed25519：CA 算法生效、叶子跟随、
// Encode → LoadCA 往返后仍可签发。
func TestNewCAAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name      string
		opts      CAOptions
		leafIs    func(crypto.Signer) bool
		pubKeyAlg x509.PublicKeyAlgorithm
	}{
		{
			name: "RSA",
			opts: CAOptions{Days: 30, Algorithm: AlgoRSA, RSABits: 2048},
			leafIs: func(k crypto.Signer) bool {
				_, ok := k.(*rsa.PrivateKey)
				return ok
			},
			pubKeyAlg: x509.RSA,
		},
		{
			name: "Ed25519",
			opts: CAOptions{Days: 30, Algorithm: AlgoEd25519},
			leafIs: func(k crypto.Signer) bool {
				_, ok := k.(ed25519.PrivateKey)
				return ok
			},
			pubKeyAlg: x509.Ed25519,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := NewCA(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if ca.Algorithm() == "" {
				t.Fatal("algorithm 为空")
			}
			caPEM, caKeyPEM, err := ca.Encode()
			if err != nil {
				t.Fatal(err)
			}
			caCert := mustCert(t, caPEM)
			if caCert.PublicKeyAlgorithm != tc.pubKeyAlg {
				t.Errorf("CA 公钥算法 = %v, want %v", caCert.PublicKeyAlgorithm, tc.pubKeyAlg)
			}

			// 叶子跟随 CA 算法，且链验证通过
			certPEM, keyPEM, err := ca.Issue(CertOptions{CommonName: "leaf", Days: 5})
			if err != nil {
				t.Fatal(err)
			}
			if !tc.leafIs(mustKey(t, keyPEM)) {
				t.Errorf("叶子私钥算法不匹配")
			}
			leaf := mustCert(t, certPEM)
			if leaf.PublicKeyAlgorithm != tc.pubKeyAlg {
				t.Errorf("叶子公钥算法 = %v, want %v", leaf.PublicKeyAlgorithm, tc.pubKeyAlg)
			}
			roots := x509.NewCertPool()
			roots.AddCert(caCert)
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
				t.Errorf("verify: %v", err)
			}
			if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
				t.Errorf("pair: %v", err)
			}

			// 往返：PKCS#8 PEM 可重新加载并继续签发
			loaded, err := LoadCA(caPEM, caKeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := loaded.Issue(CertOptions{CommonName: "again", Days: 5, Usage: UsageClient}); err != nil {
				t.Errorf("reissue: %v", err)
			}
		})
	}
}

// TestRSABitsTooSmall 验证 RSA 位数下限。
func TestRSABitsTooSmall(t *testing.T) {
	if _, err := NewCA(CAOptions{Days: 5, Algorithm: AlgoRSA, RSABits: 1024}); err == nil {
		t.Errorf("want error for 1024-bit RSA")
	}
}

// TestParseAlgorithm 覆盖算法名解析。
func TestParseAlgorithm(t *testing.T) {
	for s, want := range map[string]Algorithm{"": AlgoECDSA, "ecdsa": AlgoECDSA, "RSA": AlgoRSA, "Ed25519": AlgoEd25519} {
		got, err := ParseAlgorithm(s)
		if err != nil || got != want {
			t.Errorf("ParseAlgorithm(%q) = (%v, %v), want %v", s, got, err, want)
		}
	}
	if _, err := ParseAlgorithm("dsa"); err == nil {
		t.Errorf("ParseAlgorithm(dsa): want error")
	}
}

func mustCurve(t *testing.T, name string) elliptic.Curve {
	t.Helper()
	c, err := ParseCurve(name)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestLoadCA 验证 Encode → LoadCA 往返（含非 CA 证书与坏私钥报错）。
func TestLoadCA(t *testing.T) {
	_, certPEM, keyPEM := newTestCA(t)
	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if ca.Subject() == "" {
		t.Errorf("subject 为空")
	}

	// 加载后可继续签发
	leafPEM, leafKeyPEM, err := ca.Issue(CertOptions{CommonName: "roundtrip", Days: 5, Usage: UsageClient})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(leafPEM, leafKeyPEM); err != nil {
		t.Errorf("pair: %v", err)
	}
}

func TestLoadCAErrors(t *testing.T) {
	ca, certPEM, keyPEM := newTestCA(t)
	leafPEM, _, err := ca.Issue(CertOptions{Days: 5})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name            string
		caPEM, caKeyPEM []byte
	}{
		{"坏 CA PEM", []byte("not pem"), keyPEM},
		{"坏私钥", certPEM, []byte("not pem")},
		{"叶子当 CA", leafPEM, keyPEM},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadCA(c.caPEM, c.caKeyPEM); err == nil {
				t.Errorf("want error")
			}
		})
	}
}

// TestIssueServer 验证服务端形态：SAN 合并（CN + 附加 DNS/IP + 回环）、
// 组织字段、链验证。
func TestIssueServer(t *testing.T) {
	ca, certPEM, _ := newTestCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(mustCert(t, certPEM))

	certPEM2, keyPEM2, err := ca.Issue(CertOptions{
		CommonName:   "proxy.example.com",
		Organization: []string{"Acme"},
		DNSNames:     []string{"alt.example.com"},
		IPs:          []string{"10.0.0.5"},
		Days:         30,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustCert(t, certPEM2)
	if leaf.Subject.CommonName != "proxy.example.com" {
		t.Errorf("cn = %q", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.Organization) != 1 || leaf.Subject.Organization[0] != "Acme" {
		t.Errorf("org = %v", leaf.Subject.Organization)
	}
	for _, dns := range []string{"proxy.example.com", "alt.example.com", "localhost"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: dns}); err != nil {
			t.Errorf("verify dns %q: %v", dns, err)
		}
	}
	for _, ip := range []string{"10.0.0.5", "127.0.0.1"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: ip}); err != nil {
			t.Errorf("verify ip %q: %v", ip, err)
		}
	}
	if _, err := tls.X509KeyPair(certPEM2, keyPEM2); err != nil {
		t.Errorf("pair: %v", err)
	}
}

// TestIssueClient 验证客户端形态：仅 ClientAuth、CN 即身份、无 SAN。
func TestIssueClient(t *testing.T) {
	ca, certPEM, _ := newTestCA(t)

	certPEM2, keyPEM2, err := ca.Issue(CertOptions{CommonName: "alice", Days: 30, Usage: UsageClient})
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustCert(t, certPEM2)
	if leaf.Subject.CommonName != "alice" {
		t.Errorf("cn = %q", leaf.Subject.CommonName)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", leaf.ExtKeyUsage)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Errorf("client leaf should have no SAN: %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	roots := x509.NewCertPool()
	roots.AddCert(mustCert(t, certPEM))
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("verify client chain: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM2, keyPEM2); err != nil {
		t.Errorf("pair: %v", err)
	}
}

// TestIssueErrors 覆盖签发错误：非法 IP SAN。
func TestIssueErrors(t *testing.T) {
	ca, _, _ := newTestCA(t)
	if _, _, err := ca.Issue(CertOptions{IPs: []string{"not-an-ip"}}); err == nil {
		t.Errorf("want error for invalid IP SAN")
	}
}

// TestParseUsageAndCurve 覆盖字符串解析与默认值。
func TestParseUsageAndCurve(t *testing.T) {
	for s, want := range map[string]Usage{"": UsageServer, "server": UsageServer, "client": UsageClient, "both": UsageBoth} {
		got, err := ParseUsage(s)
		if err != nil || got != want {
			t.Errorf("ParseUsage(%q) = (%v, %v), want %v", s, got, err, want)
		}
	}
	if _, err := ParseUsage("xx"); err == nil {
		t.Errorf("ParseUsage(xx): want error")
	}
	for s, want := range map[string]bool{"P-256": true, "P-384": true, "P-521": true, "bad": false} {
		_, err := ParseCurve(s)
		if (err == nil) != want {
			t.Errorf("ParseCurve(%q) err = %v", s, err)
		}
	}
}
