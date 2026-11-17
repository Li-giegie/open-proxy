// PKCS#12（.pfx）导出：把叶子证书 + 私钥 + CA 链打包为浏览器可导入
// 的客户端证书容器。等价于：
//
//	openssl pkcs12 -export -out client.pfx -inkey client.key -in client.pem -certfile ca.pem -passout pass:…
//
// 加密方案与 openssl 3 默认一致（RFC 7292）：私钥以 PBES2
// （PBKDF2-HMAC-SHA256 + AES-256-CBC）加壳，整体以 HMAC-SHA256 MAC
// 校验；证书 bag 不加密（PKCS#12 惯例，敏感的只有私钥）。
// 键与证书 bag 带 localKeyID/friendlyName 属性，保证导入时正确配对。
package certgen

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"unicode/utf16"
)

// PKCS#12 相关 OID。
var (
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}         // data ContentInfo
	oidCertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3} // certBag
	oidShroudedKeyBag  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2} // pkcs8ShroudedKeyBag
	oidX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}     // x509Certificate bag 类型
	oidPBES2           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256CBC       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidHMACSHA256      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9} // PBKDF2 PRF
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}      // MacData 摘要 OID（openssl 实际写 sha1 而非 hmacWithSHA1）
	oidFriendlyName    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

const (
	p12Iterations = 100000 // PBKDF2 迭代次数（openssl 3 同量级）
	macKeyLen     = 20     // HMAC-SHA1 密钥长度（与摘要同长）
)

// MarshalPKCS12 把叶子证书 + 私钥打包为 PKCS#12（.pfx）DER，可导入
// 浏览器/系统证书库作为客户端证书。caChainPEM 为可选的 CA 链（各元素
// 为一张 CA 证书的 PEM），一并装入便于导入时建立信任。password 为导入
// 口令（可为空：无口令导入，Windows/macOS 均支持）。
func MarshalPKCS12(certPEM, keyPEM []byte, caChainPEM [][]byte, password string) ([]byte, error) {
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	// 属性：localKeyID 把证书与私钥配对，friendlyName 提供导入后的显示名
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	name := cert.Subject.CommonName

	// 私钥 bag：PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC）加壳
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	encKey, err := deriveKey(password, salt, p12Iterations, 32)
	if err != nil {
		return nil, err
	}
	encKeyDER, err := aesCBCEncryptPKCS7(encKey, iv, pkcs8)
	if err != nil {
		return nil, err
	}
	shroudedKey := derSEQ(
		derSEQ(oidDER(oidPBES2), derSEQ(
			derSEQ(oidDER(oidPBKDF2), derSEQ(
				derOCT(salt), intDER(p12Iterations), intDER(32),
				derSEQ(oidDER(oidHMACSHA256)),
			)),
			derSEQ(oidDER(oidAES256CBC), derOCT(iv)),
		)),
		derOCT(encKeyDER),
	)

	bags := [][]byte{
		safeBag(oidShroudedKeyBag, shroudedKey, name, id),
		safeBag(oidCertBag, derSEQ(
			oidDER(oidX509Certificate), derCTX(0, derOCT(cert.Raw)),
		), name, id),
	}
	for _, caPEM := range caChainPEM {
		ca, err := parseCertificatePEM(caPEM)
		if err != nil {
			return nil, err
		}
		bags = append(bags, safeBag(oidCertBag, derSEQ(
			oidDER(oidX509Certificate), derCTX(0, derOCT(ca.Raw)),
		), "", id))
	}

	// SafeContents →（包进 data ContentInfo）→ AuthenticatedSafe → authSafe
	safeContents := derSEQ(concat(bags...))
	authenticatedSafe := derSEQ(contentInfoData(safeContents))
	authSafe := contentInfoData(authenticatedSafe)

	// MacData：PKCS#12 专有 KDF（RFC 7292 附录 B，id=3）派生 HMAC-SHA1
	// 密钥，覆盖 AuthenticatedSafe 明文；摘要 OID 与 openssl 一致取
	// sha1（旧版 openssl / 系统导入器均支持，新版本兼容）
	macSalt := make([]byte, 16)
	if _, err := rand.Read(macSalt); err != nil {
		return nil, err
	}
	macKey := pkcs12KDF(sha1.New, password, macSalt, p12Iterations, macKeyLen, 3)
	mac := hmac.New(sha1.New, macKey)
	mac.Write(authenticatedSafe)
	macData := derSEQ(
		derSEQ(derSEQ(oidDER(oidSHA1), derNULL()), derOCT(mac.Sum(nil))),
		derOCT(macSalt),
		intDER(p12Iterations),
	)

	return derSEQ(intDER(3), authSafe, macData), nil
}

// ---------- DER 组装小工具 ----------

// der 输出 tag + DER 长度 + content。
func der(tag byte, content []byte) []byte {
	l := len(content)
	var head []byte
	switch {
	case l < 0x80:
		head = []byte{tag, byte(l)}
	case l < 0x100:
		head = []byte{tag, 0x81, byte(l)}
	case l < 0x10000:
		head = []byte{tag, 0x82, byte(l >> 8), byte(l)}
	default:
		head = []byte{tag, 0x83, byte(l >> 16), byte(l >> 8), byte(l)}
	}
	out := make([]byte, 0, len(head)+l)
	out = append(out, head...)
	return append(out, content...)
}

func derSEQ(parts ...[]byte) []byte { return der(0x30, concat(parts...)) }
func derOCT(b []byte) []byte        { return der(0x04, b) }
func derSET(parts ...[]byte) []byte { return der(0x31, concat(parts...)) }

// derCTX 输出上下文类显式标签 [tag] inner。
func derCTX(tag int, inner []byte) []byte { return der(byte(0xa0|tag), inner) }

func oidDER(oid asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(oid)
	if err != nil {
		return nil
	}
	return b
}

func intDER(n int) []byte {
	b, _ := asn1.Marshal(n)
	return b
}

func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// contentInfoData 组装 contentType=data 的 ContentInfo：
// SEQ( OID(data), [0] EXPLICIT OCTET STRING(payload) )。
func contentInfoData(payload []byte) []byte {
	return derSEQ(oidDER(oidData), derCTX(0, derOCT(payload)))
}

// safeBag 组装 SafeBag：SEQ( OID, [0] EXPLICIT value, SET(属性)可选 )。
// name 为 friendlyName（BMPString，空则省略），id 为 localKeyID；
// 多个属性整体包在一个 SET OF 里（bagAttributes 的类型）。
func safeBag(bagID asn1.ObjectIdentifier, value []byte, name string, id []byte) []byte {
	attrs := [][]byte{}
	if name != "" {
		attrs = append(attrs, derSEQ(oidDER(oidFriendlyName), derSET(bmpString(name))))
	}
	attrs = append(attrs, derSEQ(oidDER(oidLocalKeyID), derSET(derOCT(id))))
	return derSEQ(oidDER(bagID), derCTX(0, value), derSET(attrs...))
}

// bmpString 编码 PKCS#12 的 BMPString（UCS-2 大端）。
func bmpString(s string) []byte {
	runes := []rune(s)
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		out = append(out, byte(r>>8), byte(r))
	}
	return der(0x1e, out)
}

// ---------- 密码学小工具 ----------

// deriveKey PBKDF2-HMAC-SHA256 派生密钥。
func deriveKey(password string, salt []byte, iter, keyLen int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iter, keyLen)
}

// aesCBCEncryptPKCS7 AES-CBC 加密（PKCS#7 填充）。
func aesCBCEncryptPKCS7(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// parseCertificatePEM 解析 PEM 证书。
func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("证书不是合法的 PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// derNULL 输出 ASN.1 NULL（AlgorithmIdentifier 的空参数）。
func derNULL() []byte { return der(0x05, nil) }

// pkcs12KDF 是 RFC 7292 附录 B 的 PKCS#12 专有 KDF（MacData 的密钥
// 派生用它，而非标准 PBKDF2）。id：1=密钥、2=IV、3=MAC。
// 密码按 UTF-16BE 编码并以 0x0000 结尾（PKCS#12 口令编码）。
// 注意迭代语义：每一块 A_i = H^r(D||I)——先哈希 D||I，再对其结果
// 自哈希 r-1 轮（与 x/crypto pkcs12 的解码实现一致）。
func pkcs12KDF(h func() hash.Hash, password string, salt []byte, iter, keyLen int, id byte) []byte {
	digest := h()
	u, v := digest.Size(), digest.BlockSize()

	// D = id 重复 v 字节；S/P 分别循环填充到 v 的整数倍后拼接为 I
	D := bytes.Repeat([]byte{id}, v)
	padV := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		n := (len(b) + v - 1) / v * v
		out := make([]byte, n)
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	I := append(padV(salt), padV(bmpPassword(password))...)

	c := (keyLen + u - 1) / u
	out := make([]byte, 0, c*u)
	for i := 0; i < c; i++ {
		// A_i = H^r(D || I)
		digest.Reset()
		digest.Write(D)
		digest.Write(I)
		A := digest.Sum(nil)
		for j := 1; j < iter; j++ {
			digest.Reset()
			digest.Write(A)
			A = digest.Sum(nil)
		}
		out = append(out, A...)

		if i == c-1 {
			break // 最后一块无需再更新 I
		}
		// B = A 拉伸到 v 字节；I 的每个 v 字节块加 B 加 1（大端进位）
		B := make([]byte, v)
		for j := range B {
			B[j] = A[j%u]
		}
		for off := 0; off < len(I); off += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(I[off+k]) + int(B[k]) + carry
				I[off+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:keyLen]
}

// bmpPassword 口令转 PKCS#12 编码：UTF-16BE + 0x0000 终止符。
func bmpPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, len(units)*2+2)
	for i, r := range units {
		out[i*2], out[i*2+1] = byte(r>>8), byte(r)
	}
	return out
}
