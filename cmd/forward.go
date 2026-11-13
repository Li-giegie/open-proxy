/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"open-proxy/internal/httpproxy"
	"open-proxy/internal/proxycfg"
)

// forwardCmd 启动 HTTP/HTTPS 正向代理。子命令按角色/协议命名：
// forward 家族（正向代理）与 reverse 家族（反向代理）平行扩展，
// 代理链等横切能力以选项（如 --upstream）而不是命令的形式加入。
var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "HTTP/HTTPS 正向代理",
	RunE: func(cmd *cobra.Command, args []string) error {
		address, _ := cmd.Flags().GetString("address")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		dialTimeout, _ := cmd.Flags().GetDuration("dial-timeout")
		idleTimeout, _ := cmd.Flags().GetDuration("idle-timeout")
		certFile, _ := cmd.Flags().GetString("cert")
		keyFile, _ := cmd.Flags().GetString("key")
		clientCAFile, _ := cmd.Flags().GetString("client-ca")
		upstream, _ := cmd.Flags().GetString("upstream")
		upstreamUser, _ := cmd.Flags().GetString("upstream-user")
		upstreamPassword, _ := cmd.Flags().GetString("upstream-password")
		upstreamCAFile, _ := cmd.Flags().GetString("upstream-ca")
		upstreamCertFile, _ := cmd.Flags().GetString("upstream-cert")
		upstreamKeyFile, _ := cmd.Flags().GetString("upstream-key")

		var authenticator httpproxy.Authenticator
		if user != "" || password != "" {
			if user == "" || password == "" {
				return errors.New("--user 与 --password 必须同时设置")
			}
			authenticator = &httpproxy.Credentials{Username: user, Password: password}
		}

		// 代理链：出站流量（HTTP 转发与 CONNECT 隧道）先经上游代理转发
		upstreamURL, err := buildUpstreamURL(upstream, upstreamUser, upstreamPassword)
		if err != nil {
			return err
		}
		if upstreamURL != nil && upstreamURL.Scheme == "http" &&
			(upstreamCAFile != "" || upstreamCertFile != "" || upstreamKeyFile != "") {
			return errors.New("--upstream-ca/--upstream-cert/--upstream-key 仅适用于 https 上游")
		}
		var upstreamTLS *tls.Config
		if upstreamCAFile != "" || upstreamCertFile != "" || upstreamKeyFile != "" {
			var err error
			upstreamTLS, err = newClientTLSConfig(upstreamCAFile, upstreamCertFile, upstreamKeyFile)
			if err != nil {
				return fmt.Errorf("配置上游 TLS: %w", err)
			}
		}

		tlsConf, err := newTLSConfig(certFile, keyFile, clientCAFile)
		if err != nil {
			return err
		}

		proxy, err := httpproxy.New(httpproxy.Options{
			Authenticator:     authenticator,
			DialTimeout:       dialTimeout,
			TunnelIdleTimeout: idleTimeout,
			Upstream:          upstreamURL,
			UpstreamTLS:       upstreamTLS,
		})
		if err != nil {
			return err
		}
		srv := &http.Server{
			Addr:    address,
			Handler: proxy,
			// 只限制读头部与 keep-alive 空闲。不能设置整体 Read/Write
			// 超时，否则会截断耗时的上传/下载
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
			TLSConfig:         tlsConf,
		}

		slog.Info("proxy listening",
			"address", address,
			"auth", authenticator != nil,
			"upstream", upstreamURL != nil,
			"upstream_tls", upstreamURL != nil && upstreamURL.Scheme == "https",
			"tls", tlsConf != nil,
			"mtls", tlsConf != nil && tlsConf.ClientAuth == tls.RequireAndVerifyClientCert,
		)
		if tlsConf != nil {
			return srv.ListenAndServeTLS("", "")
		}
		return srv.ListenAndServe()
	},
}

// buildUpstreamURL 构造上游代理 URL（代理链），语义见 proxycfg.UpstreamURL。
func buildUpstreamURL(raw, user, password string) (*url.URL, error) {
	return proxycfg.UpstreamURL(raw, user, password)
}

func init() {
	rootCmd.AddCommand(forwardCmd)
	forwardCmd.Flags().StringP("address", "a", ":1080", "监听地址")
	forwardCmd.Flags().String("user", "", "代理认证用户名（与 --password 一起启用 Basic 认证）")
	forwardCmd.Flags().String("password", "", "代理认证密码")
	forwardCmd.Flags().Duration("dial-timeout", 10*time.Second, "连接上游的超时时间")
	forwardCmd.Flags().Duration("idle-timeout", 2*time.Minute, "CONNECT 隧道空闲超时时间")
	forwardCmd.Flags().String("upstream", "", "上游正向代理地址（启用代理链），形如 http://host:port 或 https://host:port，可带 user:pass 认证")
	forwardCmd.Flags().String("upstream-user", "", "上游代理认证用户名（与 --upstream-password 一起对上游做 Basic 认证）")
	forwardCmd.Flags().String("upstream-password", "", "上游代理认证密码（密码含特殊字符时优先用这两个 flag 而不是 URL userinfo）")
	forwardCmd.Flags().String("upstream-ca", "", "校验 https 上游代理 TLS 证书的 CA PEM 文件（默认信任系统根证书）")
	forwardCmd.Flags().String("upstream-cert", "", "与 https 上游 mTLS 时出示的客户端证书 PEM（与 --upstream-key 同时设置）")
	forwardCmd.Flags().String("upstream-key", "", "与 https 上游 mTLS 时出示的客户端私钥 PEM")
	forwardCmd.Flags().String("cert", "", "服务端 TLS 证书 PEM 文件（与 --key 同时设置启用 TLS 监听）")
	forwardCmd.Flags().String("key", "", "服务端 TLS 私钥 PEM 文件")
	forwardCmd.Flags().String("client-ca", "", "客户端证书签发 CA 的 PEM 文件（在 TLS 基础上启用 mTLS）")
}
