/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/Li-giegie/open-proxy/internal/netutil"
	"github.com/Li-giegie/open-proxy/internal/socks5"
)

// socks5Cmd 启动 SOCKS5 正向代理。与 forward 家族平行扩展：认证走
// SOCKS5 用户名/密码子协商（RFC 1929）而不是 HTTP Basic。监听端支持
// 明文 / TLS / mTLS（复用 netutil.ServerTLS）。注意 SOCKS5 over TLS
// 非 RFC 标准（主流客户端如 curl 不支持），客户端需同样以 TLS 接入。
var socks5Cmd = &cobra.Command{
	Use:   "socks5",
	Short: "SOCKS5 正向代理",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := loadFlagsFromConfig(cmd); err != nil {
			return err
		}
		address, _ := cmd.Flags().GetString("address")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		dialTimeout, _ := cmd.Flags().GetDuration("dial-timeout")
		idleTimeout, _ := cmd.Flags().GetDuration("idle-timeout")
		certFile, _ := cmd.Flags().GetString("cert")
		keyFile, _ := cmd.Flags().GetString("key")
		clientCAFile, _ := cmd.Flags().GetString("client-ca")

		var authenticator socks5.Authenticator
		if user != "" || password != "" {
			if user == "" || password == "" {
				return errors.New("--user 与 --password 必须同时设置")
			}
			authenticator = &socks5.Credentials{Username: user, Password: password}
		}

		tlsConf, err := netutil.ServerTLS(certFile, keyFile, clientCAFile)
		if err != nil {
			return err
		}

		proxy, err := socks5.New(socks5.Options{
			Authenticator: authenticator,
			DialTimeout:   dialTimeout,
			IdleTimeout:   idleTimeout,
		})
		if err != nil {
			return err
		}

		ln, err := net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("监听 %s: %w", address, err)
		}
		// TLS 监听：把裸 TCP listener 包成 TLS listener，Proxy.Serve 无感知
		if tlsConf != nil {
			ln = tls.NewListener(ln, tlsConf)
		}

		slog.Info("socks5 proxy listening",
			"address", address,
			"auth", authenticator != nil,
			"tls", tlsConf != nil,
			"mtls", tlsConf != nil && tlsConf.ClientAuth == tls.RequireAndVerifyClientCert,
		)
		return proxy.Serve(ln)
	},
}

func init() {
	rootCmd.AddCommand(socks5Cmd)
	socks5Cmd.Flags().StringP("config", "c", "", "JSON 配置文件（键名与 flag 一致，与命令行参数二选一，示例见 configs/socks5.example.json）")
	socks5Cmd.Flags().StringP("address", "a", ":1080", "监听地址")
	socks5Cmd.Flags().String("user", "", "代理认证用户名（与 --password 一起启用用户名/密码认证）")
	socks5Cmd.Flags().String("password", "", "代理认证密码")
	socks5Cmd.Flags().Duration("dial-timeout", 10*time.Second, "连接目标的超时时间")
	socks5Cmd.Flags().Duration("idle-timeout", 2*time.Minute, "CONNECT 隧道空闲超时时间")
	socks5Cmd.Flags().String("cert", "", "服务端 TLS 证书 PEM 文件（与 --key 同时设置启用 TLS 监听）")
	socks5Cmd.Flags().String("key", "", "服务端 TLS 私钥 PEM 文件")
	socks5Cmd.Flags().String("client-ca", "", "客户端证书签发 CA 的 PEM 文件（在 TLS 基础上启用 mTLS）")
}
