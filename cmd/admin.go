/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/Li-giegie/open-proxy/internal/admin"
)

// adminCmd 启动代理管理中心：Web UI + REST API，统一创建/启停
// forward、reverse 代理资源。资源以进程内实例运行，配置持久化到
// JSON 文件，重启后自动恢复。监听端支持明文 / TLS / mTLS（复用
// newTLSConfig），与 forward、reverse 命令一致。
var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "代理管理中心（Web UI + REST API）",
	RunE: func(cmd *cobra.Command, args []string) error {
		address, _ := cmd.Flags().GetString("address")
		dataFile, _ := cmd.Flags().GetString("data")
		user, _ := cmd.Flags().GetString("user")
		password, _ := cmd.Flags().GetString("password")
		certFile, _ := cmd.Flags().GetString("cert")
		keyFile, _ := cmd.Flags().GetString("key")
		clientCAFile, _ := cmd.Flags().GetString("client-ca")

		if (user == "") != (password == "") {
			return errors.New("--user 与 --password 必须同时设置")
		}

		// 管理中心自身的监听端 TLS/mTLS；Basic 认证凭证经 TLS 传输
		// 才不会明文暴露，暴露在不可信网络时建议启用
		tlsConf, err := newTLSConfig(certFile, keyFile, clientCAFile)
		if err != nil {
			return err
		}

		mgr, err := admin.NewManager(admin.NewStore(dataFile), slog.Default())
		if err != nil {
			return err
		}

		srv := &http.Server{
			Addr:              address,
			Handler:           admin.Handler(mgr, user, password),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig:         tlsConf,
		}

		slog.Info("admin listening",
			"address", address,
			"data", dataFile,
			"auth", user != "",
			"tls", tlsConf != nil,
			"mtls", tlsConf != nil && tlsConf.ClientAuth == tls.RequireAndVerifyClientCert,
			"resources", len(mgr.List()),
		)
		if tlsConf != nil {
			return srv.ListenAndServeTLS("", "")
		}
		return srv.ListenAndServe()
	},
}

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.Flags().StringP("address", "a", "127.0.0.1:8090", "管理中心监听地址")
	adminCmd.Flags().String("data", "proxies.json", "资源持久化文件（JSON，重启后按此恢复资源）")
	adminCmd.Flags().String("user", "", "管理中心 Basic 认证用户名（与 --password 同时设置）")
	adminCmd.Flags().String("password", "", "管理中心 Basic 认证密码")
	adminCmd.Flags().String("cert", "", "管理中心 TLS 证书 PEM 文件（与 --key 同时设置启用 TLS 监听）")
	adminCmd.Flags().String("key", "", "管理中心 TLS 私钥 PEM 文件")
	adminCmd.Flags().String("client-ca", "", "管理中心客户端证书签发 CA 的 PEM 文件（在 TLS 基础上启用 mTLS）")
}
