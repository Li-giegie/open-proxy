package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd 是 open-proxy 的入口命令：forward（正向代理）、
// reverse（反向代理）与 admin（代理资源管理中心）三个子命令。
var rootCmd = &cobra.Command{
	Use:   "open-proxy",
	Short: "HTTP/HTTPS 正向代理、反向代理与代理资源管理中心",
	Long: `open-proxy 提供三个子命令：

  forward  HTTP/HTTPS 正向代理：客户端认证、代理链（上游代理）、
           TLS/mTLS 监听，出站流量可经上游代理转发
  reverse  HTTP 反向代理：多 backend 轮询负载均衡、监听 TLS/mTLS、
           对 backend 的 TLS/mTLS
  admin    代理资源管理中心：Web UI + REST API，动态创建/启停/删除
           代理资源，支持多用户动态管理与运行监控

详见 README.md。`,
}

// Execute adds all child commands to the root command and sets flags
// appropriately. This is called by main.main(). It only needs to happen
// once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
