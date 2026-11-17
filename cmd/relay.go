/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Li-giegie/open-proxy/internal/relay"
)

// relayCmd 启动裸 TCP 中继：多上游加权选择 + 拨号 failover，本地与
// 上游均支持 TLS/mTLS。配置文件与命令行参数**二选一**：
//   - 配置文件：--config 指向 JSON（示例见 configs/relay.example.json），
//     适合多上游且各上游 TLS 配置不同的场景；
//   - 命令行：--address/--upstream 等系列 flag，适合简单场景。
//     上游 TLS 的三个 flag 作用于全部上游，每个上游各不相同的 TLS
//     只能经配置文件表达。
//
// 两者同时显式给出会直接报错，不存在覆盖关系。
var relayCmd = &cobra.Command{
	Use:   "relay",
	Short: "裸 TCP 中继（多上游加权 + failover，TLS/mTLS）",
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		cfg, err := relayConfig(flags)
		if err != nil {
			return err
		}
		r, err := relay.New(cfg)
		if err != nil {
			return err
		}
		return r.ListenAndServe()
	},
}

// relayConfig 组装中继配置：给了 --config 走纯配置文件路径（不得混用
// 其他 flag），否则从命令行 flag 构建。
func relayConfig(flags *pflag.FlagSet) (*relay.Config, error) {
	path, _ := flags.GetString("config")
	if path != "" {
		if err := rejectFlagMix(flags); err != nil {
			return nil, err
		}
		return relay.Load(path)
	}

	cfg := &relay.Config{}
	cfg.Listen, _ = flags.GetString("address")

	upstreams, _ := flags.GetStringArray("upstream")
	parsed, err := parseUpstreams(upstreams)
	if err != nil {
		return nil, err
	}
	cfg.Upstreams = parsed
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("未配置上游：使用 --upstream 或 --config")
	}

	// 监听端 TLS（三个字段全空视同未配置，即明文）
	cert, _ := flags.GetString("cert")
	key, _ := flags.GetString("key")
	clientCA, _ := flags.GetString("client-ca")
	if cert != "" || key != "" || clientCA != "" {
		cfg.ListenTLS = &relay.TLSSettings{Cert: cert, Key: key, ClientCA: clientCA}
	}

	// 上游 TLS flags：作用于全部上游（每上游不同的 TLS 走配置文件）
	ca, _ := flags.GetString("upstream-ca")
	upCert, _ := flags.GetString("upstream-cert")
	upKey, _ := flags.GetString("upstream-key")
	if ca != "" || upCert != "" || upKey != "" {
		for i := range cfg.Upstreams {
			cfg.Upstreams[i].TLS = &relay.ClientTLSSettings{CA: ca, Cert: upCert, Key: upKey}
		}
	}

	dialTimeout, _ := flags.GetDuration("dial-timeout")
	cfg.DialTimeout = dialTimeout.String()
	idleTimeout, _ := flags.GetDuration("idle-timeout")
	cfg.IdleTimeout = idleTimeout.String()
	return cfg, nil
}

// parseUpstreams 解析 --upstream 值列表：每项形如 address 或
// address=weight（weight 缺省 1），例如 10.0.0.1:9001=3。
func parseUpstreams(values []string) ([]relay.UpstreamConfig, error) {
	out := make([]relay.UpstreamConfig, 0, len(values))
	for i, v := range values {
		cfg := relay.UpstreamConfig{Weight: 1}
		addr, w, found := strings.Cut(v, "=")
		if found {
			n, err := strconv.Atoi(strings.TrimSpace(w))
			if err != nil || n < 1 {
				return nil, fmt.Errorf("无效的 --upstream %q（weight 需为 >= 1 的整数）", v)
			}
			cfg.Weight = n
		}
		cfg.Address = strings.TrimSpace(addr)
		if cfg.Address == "" {
			return nil, fmt.Errorf("无效的 --upstream %q（address 不能为空）", values[i])
		}
		out = append(out, cfg)
	}
	return out, nil
}

func init() {
	rootCmd.AddCommand(relayCmd)
	relayCmd.Flags().StringP("config", "c", "", "中继 JSON 配置文件路径（示例见 configs/relay.example.json），与命令行参数二选一（混用报错）")
	relayCmd.Flags().StringP("address", "a", ":9000", "监听地址")
	relayCmd.Flags().StringArray("upstream", nil, "上游地址，形如 host:port 或 host:port=weight（weight 缺省 1），可重复多次")
	relayCmd.Flags().String("cert", "", "服务端 TLS 证书 PEM 文件（与 --key 同时设置启用 TLS 监听）")
	relayCmd.Flags().String("key", "", "服务端 TLS 私钥 PEM 文件")
	relayCmd.Flags().String("client-ca", "", "客户端证书签发 CA 的 PEM 文件（在 TLS 基础上启用 mTLS）")
	relayCmd.Flags().String("upstream-ca", "", "校验 https 上游 TLS 证书的 CA PEM 文件（作用于全部上游）")
	relayCmd.Flags().String("upstream-cert", "", "与上游 mTLS 时出示的客户端证书 PEM（与 --upstream-key 同时设置，作用于全部上游）")
	relayCmd.Flags().String("upstream-key", "", "与上游 mTLS 时出示的客户端私钥 PEM（作用于全部上游）")
	relayCmd.Flags().Duration("dial-timeout", 10*time.Second, "连接上游的超时时间")
	relayCmd.Flags().Duration("idle-timeout", 2*time.Minute, "透传阶段空闲超时时间")
}
