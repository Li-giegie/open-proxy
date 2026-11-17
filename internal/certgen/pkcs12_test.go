package certgen

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

// PFX 解析用的最小结构（测试自校验用）。
type tContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type tMacData struct {
	Mac struct {
		Algo struct {
			Algorithm asn1.ObjectIdentifier
		}
		Digest []byte
	}
	MacSalt    []byte
	Iterations int
}

type tPFX struct {
	Version  int
	AuthSafe tContentInfo
	MacData  tMacData
}

type tSafeBag struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"tag:0,explicit"`
}

type tEPKI struct {
	Algo      pkixAlgorithmIdentifier
	Encrypted []byte
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type tPBES2 struct {
	KDF  pkixAlgorithmIdentifier
	Schm pkixAlgorithmIdentifier
}

type tPBKDF2 struct {
	Salt   []byte
	Iter   int
	KeyLen int `asn1:"optional"`
	PRF    pkixAlgorithmIdentifier
}

// TestMarshalPKCS12 验证导出的 PFX：结构合法、MAC 对正确口令通过 /
// 错误口令失败、私钥可解出并与原私钥一致、证书与 CA 链都在容器里。
func TestMarshalPKCS12(t *testing.T) {
	ca, err := NewCA(CAOptions{Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _, err := ca.Encode()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.Issue(CertOptions{CommonName: "p12-client", Days: 30, Usage: UsageClient})
	if err != nil {
		t.Fatal(err)
	}

	pfx, err := MarshalPKCS12(certPEM, keyPEM, [][]byte{caPEM}, "pass123")
	if err != nil {
		t.Fatal(err)
	}

	var top tPFX
	if _, err := asn1.Unmarshal(pfx, &top); err != nil {
		t.Fatalf("解析 PFX: %v", err)
	}
	if top.Version != 3 {
		t.Errorf("version = %d, want 3", top.Version)
	}

	// MAC：正确口令复算一致，错误口令不一致
	var authSafeContent []byte
	if _, err := asn1.Unmarshal(top.AuthSafe.Content.Bytes, &authSafeContent); err != nil {
		t.Fatalf("解析 authSafe: %v", err)
	}
	macOK := func(password string) bool {
		key := pkcs12KDF(sha1.New, password, top.MacData.MacSalt, top.MacData.Iterations, macKeyLen, 3)
		m := hmac.New(sha1.New, key)
		m.Write(authSafeContent)
		return hmac.Equal(m.Sum(nil), top.MacData.Mac.Digest)
	}
	if !macOK("pass123") {
		t.Errorf("正确口令的 MAC 校验失败")
	}
	if macOK("wrong") {
		t.Errorf("错误口令的 MAC 竟然通过")
	}

	// AuthenticatedSafe → SafeContents → bags
	var authenticatedSafe []tContentInfo
	if _, err := asn1.Unmarshal(authSafeContent, &authenticatedSafe); err != nil {
		t.Fatalf("解析 authenticatedSafe: %v", err)
	}
	if len(authenticatedSafe) != 1 || !authenticatedSafe[0].ContentType.Equal(oidData) {
		t.Fatalf("authenticatedSafe 结构异常: %+v", authenticatedSafe)
	}
	var safeContents []byte
	if _, err := asn1.Unmarshal(authenticatedSafe[0].Content.Bytes, &safeContents); err != nil {
		t.Fatalf("解析 safeContents: %v", err)
	}
	var bags []tSafeBag
	if _, err := asn1.Unmarshal(safeContents, &bags); err != nil {
		t.Fatalf("解析 bags: %v", err)
	}
	if len(bags) != 3 { // 私钥 + 叶子证书 + CA 证书
		t.Fatalf("bags = %d, want 3", len(bags))
	}

	// 私钥 bag：PBES2 解密回 PKCS#8，与原私钥比对
	if !bags[0].ID.Equal(oidShroudedKeyBag) {
		t.Fatalf("第一个 bag 不是私钥 bag: %v", bags[0].ID)
	}
	var epki tEPKI
	if _, err := asn1.Unmarshal(bags[0].Value.Bytes, &epki); err != nil {
		t.Fatalf("解析加密私钥: %v", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		t.Fatalf("私钥加密不是 PBES2: %v", epki.Algo.Algorithm)
	}
	var pbes2 tPBES2
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &pbes2); err != nil {
		t.Fatalf("解析 PBES2 参数: %v", err)
	}
	if !pbes2.KDF.Algorithm.Equal(oidPBKDF2) || !pbes2.Schm.Algorithm.Equal(oidAES256CBC) {
		t.Fatalf("PBES2 参数异常: KDF=%v Scheme=%v", pbes2.KDF.Algorithm, pbes2.Schm.Algorithm)
	}
	var kdf tPBKDF2
	if _, err := asn1.Unmarshal(pbes2.KDF.Parameters.FullBytes, &kdf); err != nil {
		t.Fatalf("解析 PBKDF2 参数: %v", err)
	}
	if kdf.KeyLen != 32 {
		t.Errorf("keyLen = %d, want 32", kdf.KeyLen)
	}
	key, err := pbkdf2.Key(sha256.New, "pass123", kdf.Salt, kdf.Iter, kdf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(pbes2.Schm.Parameters.FullBytes, &iv); err != nil {
		t.Fatalf("解析 IV: %v", err)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(epki.Encrypted)%aes.BlockSize != 0 {
		t.Fatalf("密文长度 %d 不是块对齐", len(epki.Encrypted))
	}
	plain := make([]byte, len(epki.Encrypted))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, epki.Encrypted)
	pad := int(plain[len(plain)-1]) // PKCS#7 去填充
	if pad == 0 || pad > aes.BlockSize || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		t.Fatalf("PKCS#7 填充非法: %d", pad)
	}
	pkcs8 := plain[:len(plain)-pad]

	origKey, err := parseKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	origPKCS8, err := x509.MarshalPKCS8PrivateKey(origKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkcs8, origPKCS8) {
		t.Errorf("解出的私钥与原私钥不一致")
	}

	// 证书 bag：叶子与 CA 的 DER 都在容器里
	wantCerts := [][]byte{mustCert(t, certPEM).Raw, mustCert(t, caPEM).Raw}
	gotCerts := 0
	for _, b := range bags[1:] {
		if !b.ID.Equal(oidCertBag) {
			continue
		}
		var certBag struct {
			CertID asn1.ObjectIdentifier
			Value  asn1.RawValue `asn1:"tag:0,explicit"`
		}
		if _, err := asn1.Unmarshal(b.Value.Bytes, &certBag); err != nil {
			t.Fatalf("解析 certBag: %v", err)
		}
		var der []byte
		if _, err := asn1.Unmarshal(certBag.Value.Bytes, &der); err != nil {
			t.Fatalf("解析证书 DER: %v", err)
		}
		for _, want := range wantCerts {
			if bytes.Equal(der, want) {
				gotCerts++
				break
			}
		}
	}
	if gotCerts != len(wantCerts) {
		t.Errorf("容器内证书匹配数 = %d, want %d", gotCerts, len(wantCerts))
	}
}
