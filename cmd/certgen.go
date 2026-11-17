/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Li-giegie/open-proxy/internal/certgen"
)

// certgenCmd 证书工具，两种工作模式：
//   - 生成：不带 --ca 时创建自签 CA 并签发一张服务端证书，输出
//     ca.pem / ca-key.pem / cert.pem / key.pem；
//   - 签发：给 --ca 与 --ca-key（生成模式产出的 CA）时由该 CA 签发
//     一张新的叶子证书，输出 cert.pem / key.pem。
//
// 叶子证书参数：--cn / --days / --org / --dns / --ip / --usage
// （client：mTLS 出示，CN 即身份；server/both：SAN 覆盖 --cn、--dns、
// --ip 外加 localhost、127.0.0.1、::1）。
// CA 参数（仅生成模式）：--ca-cn / --ca-days / --algorithm / --curve /
// --rsa-bits。已存在同名文件时拒绝覆盖。配置文件与命令行参数二选一。
var certgenCmd = &cobra.Command{
	Use:   "certgen",
	Short: "生成/签发证书（自签 CA + 叶子证书，或由已有 CA 签发）",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadFlagsFromConfig(cmd); err != nil {
			return err
		}
		flags := cmd.Flags()
		out, _ := flags.GetString("out")
		caFile, _ := flags.GetString("ca")
		caKeyFile, _ := flags.GetString("ca-key")

		if err := os.MkdirAll(out, 0o755); err != nil {
			return fmt.Errorf("创建输出目录 %s: %w", out, err)
		}

		if caFile != "" || caKeyFile != "" {
			if caFile == "" || caKeyFile == "" {
				return errors.New("--ca 与 --ca-key 必须同时设置（签发模式）")
			}
			return issueCert(flags, caFile, caKeyFile, out)
		}
		return generateCert(flags, out)
	},
}

// generateCert 生成模式：NewCA → 签发服务端证书，写四个文件
// （--pfx-pass 非空时额外写 cert.pfx，浏览器可直接导入）。
func generateCert(flags *pflag.FlagSet, out string) error {
	files := []string{"ca.pem", "ca-key.pem", "cert.pem", "key.pem"}
	if mustString(flags, "pfx-pass") != "" || flags.Changed("pfx-pass") {
		files = append(files, "cert.pfx")
	}
	for _, name := range files {
		if err := refuseExists(out, name); err != nil {
			return err
		}
	}

	curve, err := certgen.ParseCurve(mustString(flags, "curve"))
	if err != nil {
		return err
	}
	algorithm, err := certgen.ParseAlgorithm(mustString(flags, "algorithm"))
	if err != nil {
		return err
	}
	ca, err := certgen.NewCA(certgen.CAOptions{
		CommonName:   mustString(flags, "ca-cn"),
		Organization: mustStringSlice(flags, "org"),
		Days:         mustInt(flags, "ca-days"),
		Algorithm:    algorithm,
		Curve:        curve,
		RSABits:      mustInt(flags, "rsa-bits"),
	})
	if err != nil {
		return err
	}
	caPEM, caKeyPEM, err := ca.Encode()
	if err != nil {
		return err
	}

	certOpts, err := certOptsFromFlags(flags)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.Issue(certOpts)
	if err != nil {
		return err
	}

	if err := writeFiles(out, map[string][]byte{
		"ca.pem":     caPEM,
		"ca-key.pem": caKeyPEM,
		"cert.pem":   certPEM,
		"key.pem":    keyPEM,
	}); err != nil {
		return err
	}
	if err := maybeWritePFX(flags, out, certPEM, keyPEM, caPEM); err != nil {
		return err
	}

	slog.Info("certificates generated", "ca", mustString(flags, "ca-cn"), "algorithm", algorithm, "cn", certOpts.CommonName, "dir", out)
	fmt.Printf("已生成（目录 %s）：\n", out)
	fmt.Printf("  ca.pem     自签 CA %s（分发给客户端作信任根，或作为资源的 client_ca 启用 mTLS）\n", mustString(flags, "ca-cn"))
	fmt.Println("  ca-key.pem CA 私钥（妥善保管，可用于继续签发：certgen --ca ca.pem --ca-key ca-key.pem --usage client --cn alice）")
	fmt.Printf("  cert.pem   %s证书（SAN 含 %s、%s、127.0.0.1、::1）\n", certOpts.Usage, certOpts.CommonName, joinOr(mustStringSlice(flags, "dns"), "、"))
	fmt.Println("  key.pem    私钥")
	if flags.Changed("pfx-pass") {
		fmt.Println("  cert.pfx   PKCS#12（叶子证书+私钥，浏览器/系统导入用，口令见 --pfx-pass" + func() string {
			if c, _ := flags.GetBool("pfx-chain"); c {
				return "，含 CA 链"
			}
			return ""
		}() + "）")
	}
	return nil
}

// issueCert 签发模式：加载已有 CA → 签发叶子证书，写两个文件
// （--pfx-pass 非空时额外写 cert.pfx，浏览器可直接导入）。
func issueCert(flags *pflag.FlagSet, caFile, caKeyFile, out string) error {
	files := []string{"cert.pem", "key.pem"}
	if mustString(flags, "pfx-pass") != "" || flags.Changed("pfx-pass") {
		files = append(files, "cert.pfx")
	}
	for _, name := range files {
		if err := refuseExists(out, name); err != nil {
			return err
		}
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("读取 %s: %w", caFile, err)
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return fmt.Errorf("读取 %s: %w", caKeyFile, err)
	}
	ca, err := certgen.LoadCA(caPEM, caKeyPEM)
	if err != nil {
		return err
	}

	certOpts, err := certOptsFromFlags(flags)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.Issue(certOpts)
	if err != nil {
		return err
	}
	if err := writeFiles(out, map[string][]byte{
		"cert.pem": certPEM,
		"key.pem":  keyPEM,
	}); err != nil {
		return err
	}
	if err := maybeWritePFX(flags, out, certPEM, keyPEM, caPEM); err != nil {
		return err
	}

	slog.Info("certificate issued", "cn", certOpts.CommonName, "usage", certOpts.Usage, "ca", caFile, "dir", out)
	fmt.Printf("已签发 %s 证书（目录 %s，签发 CA %s，过期时间 %s）：\n", certOpts.Usage, out, caFile, ca.NotAfter().Format("2006-01-02"))
	fmt.Println("  cert.pem  证书" + func() string {
		if certOpts.Usage == certgen.UsageClient {
			return "（mTLS 时出示，CN 即身份 " + certOpts.CommonName + "）"
		}
		return "（SAN 含 " + certOpts.CommonName + joinOr(mustStringSlice(flags, "dns"), "、") + "、localhost、127.0.0.1、::1）"
	}())
	fmt.Println("  key.pem   私钥")
	if flags.Changed("pfx-pass") {
		fmt.Println("  cert.pfx  PKCS#12（叶子证书+私钥，浏览器/系统导入用，口令见 --pfx-pass" + func() string {
			if c, _ := flags.GetBool("pfx-chain"); c {
				return "，含 CA 链"
			}
			return ""
		}() + "）")
	}
	return nil
}

// maybeWritePFX 在 --pfx-pass 显式给出（含空口令）时把叶子证书 + 私钥
// 导出为 PKCS#12 的 cert.pfx（与 openssl 的 `pkcs12 -export -in cert.pem
// -inkey key.pem` 语义一致）；--pfx-chain 时一并打包 CA 证书（对应
// openssl 的 -certfile，浏览器导入客户端证书时不需要，且会把 CA 装进
// 导入方的信任库）。
func maybeWritePFX(flags *pflag.FlagSet, out string, certPEM, keyPEM, caPEM []byte) error {
	if !flags.Changed("pfx-pass") {
		return nil
	}
	var chain [][]byte
	if includeChain, _ := flags.GetBool("pfx-chain"); includeChain {
		chain = append(chain, caPEM)
	}
	pfx, err := certgen.MarshalPKCS12(certPEM, keyPEM, chain, mustString(flags, "pfx-pass"))
	if err != nil {
		return err
	}
	return writeFiles(out, map[string][]byte{"cert.pfx": pfx})
}

// certOptsFromFlags 从命令行 flag 组装叶子证书选项。
func certOptsFromFlags(flags *pflag.FlagSet) (certgen.CertOptions, error) {
	usage, err := certgen.ParseUsage(mustString(flags, "usage"))
	if err != nil {
		return certgen.CertOptions{}, err
	}
	return certgen.CertOptions{
		CommonName:   mustString(flags, "cn"),
		Organization: mustStringSlice(flags, "org"),
		DNSNames:     mustStringSlice(flags, "dns"),
		IPs:          mustStringSlice(flags, "ip"),
		Days:         mustInt(flags, "days"),
		Usage:        usage,
	}, nil
}

// refuseExists 拒绝覆盖已有文件，避免误操作覆盖线上证书。
func refuseExists(dir, name string) error {
	if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
		return fmt.Errorf("%s 已存在，拒绝覆盖（换一个 --out 目录或先移走旧文件）", filepath.Join(dir, name))
	}
	return nil
}

// writeFiles 写出全部产物（0600）。
func writeFiles(out string, files map[string][]byte) error {
	for name, data := range files {
		path := filepath.Join(out, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("写入 %s: %w", path, err)
		}
	}
	return nil
}

// joinOr 逗号连接非空列表（打印用），空列表返回空串。
func joinOr(list []string, sep string) string {
	out := ""
	for i, s := range list {
		if s == "" {
			continue
		}
		if i > 0 && out != "" {
			out += sep
		}
		out += s
	}
	return out
}

func mustString(flags *pflag.FlagSet, name string) string {
	v, _ := flags.GetString(name)
	return v
}

func mustStringSlice(flags *pflag.FlagSet, name string) []string {
	v, _ := flags.GetStringSlice(name)
	return v
}

func mustInt(flags *pflag.FlagSet, name string) int {
	v, _ := flags.GetInt(name)
	return v
}

func init() {
	rootCmd.AddCommand(certgenCmd)
	certgenCmd.Flags().StringP("config", "c", "", "JSON 配置文件（键名与 flag 一致，与命令行参数二选一，示例见 configs/certgen.example.json）")
	// 叶子证书参数（生成与签发模式通用）
	certgenCmd.Flags().String("cn", "open-proxy", "叶子证书 Common Name：服务端形态为域名或 IP（写入 SAN），客户端形态为身份名")
	certgenCmd.Flags().Int("days", 3650, "叶子证书有效期天数")
	certgenCmd.Flags().StringSlice("org", nil, "主题 Organization 字段（可重复）")
	certgenCmd.Flags().StringSlice("dns", nil, "附加 DNS SAN（可重复，服务端/双向形态生效）")
	certgenCmd.Flags().StringSlice("ip", nil, "附加 IP SAN（可重复，服务端/双向形态生效）")
	certgenCmd.Flags().String("usage", "server", "叶子证书用途：server（默认）/ client（mTLS 身份）/ both")
	// CA 参数（仅生成模式）
	certgenCmd.Flags().String("ca-cn", "open-proxy-ca", "CA 的 Common Name")
	certgenCmd.Flags().Int("ca-days", 3650, "CA 有效期天数")
	certgenCmd.Flags().String("algorithm", "ECDSA", "签名算法：ECDSA（默认）/ RSA / Ed25519（叶子证书跟随 CA 算法）")
	certgenCmd.Flags().String("curve", "P-256", "ECDSA 曲线：P-256（默认）/ P-384 / P-521")
	certgenCmd.Flags().Int("rsa-bits", 2048, "RSA 位数（仅 --algorithm RSA 时生效，至少 2048）")
	// 通用
	certgenCmd.Flags().StringP("out", "o", "certs", "输出目录（已存在同名证书文件时拒绝覆盖）")
	certgenCmd.Flags().String("pfx-pass", "", "额外导出 cert.pfx（PKCS#12，含叶子证书+私钥，与 openssl pkcs12 -export 默认语义一致，浏览器/系统可直接导入）的口令；显式给空值则导出无口令的 pfx")
	certgenCmd.Flags().Bool("pfx-chain", false, "PFX 一并包含 CA 证书（对应 openssl -certfile；浏览器导入客户端证书不需要，且会把 CA 装进导入方信任库）")
	certgenCmd.Flags().String("ca", "", "签发模式：已有 CA 证书 PEM 文件（与 --ca-key 同时设置）")
	certgenCmd.Flags().String("ca-key", "", "签发模式：已有 CA 私钥 PEM 文件（与 --ca 同时设置）")
}
