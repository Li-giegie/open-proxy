package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd 是 open-proxy 的入口命令，聚合五个服务子命令与证书工具。
var rootCmd = &cobra.Command{
	Use:   "open-proxy",
	Short: "正向 / 反向 / SOCKS5 代理、TCP 中继与代理资源管理中心",
	Long: `open-proxy 提供六个子命令：

  forward  HTTP/HTTPS 正向代理：客户端认证、代理链（上游代理）、
           TLS/mTLS 监听，出站流量可经上游代理转发
  reverse  HTTP 反向代理：多 backend 轮询负载均衡、监听 TLS/mTLS、
           对 backend 的 TLS/mTLS
  socks5   SOCKS5 正向代理（CONNECT）：用户名/密码认证（RFC 1929）、
           TLS/mTLS 监听
  relay    裸 TCP 中继：多上游加权选择、拨号失败自动切换（failover），
           本地与上游均支持 TLS/mTLS
  admin    代理资源管理中心：Web UI + REST API，动态创建/启停/编辑/删除
           各类代理资源，含证书工具，支持多用户动态管理与运行监控
  certgen  证书工具：生成自签 CA + 服务端证书，或由已有 CA 签发
           客户端/服务端证书（ECDSA / RSA / Ed25519）

所有服务子命令同时支持命令行参数与 JSON 配置文件（-c/--config），
两者二选一，不可混用。详见 README.md。`,
}

// Execute 运行根命令，出错时以非零码退出（main.main 调用）。
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
