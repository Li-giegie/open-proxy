/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Li-giegie/open-proxy/internal/reverseproxy"
)

// readPEMFiles 读取 PEM 证书文件，空路径返回 nil。
func readPEMFiles(paths ...string) ([][]byte, error) {
	out := make([][]byte, len(paths))
	for i, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("读取 %s: %w", p, err)
		}
		out[i] = data
	}
	return out, nil
}

// reverseCmd 启动 HTTP 反向代理，监听端支持明文 / TLS / mTLS
// （复用 newTLSConfig），与 forward 家族平行扩展。
var reverseCmd = &cobra.Command{
	Use:   "reverse",
	Short: "HTTP 反向代理",
	RunE: func(cmd *cobra.Command, args []string) error {
		address, _ := cmd.Flags().GetString("address")
		backends, _ := cmd.Flags().GetStringSlice("backend")
		certFile, _ := cmd.Flags().GetString("cert")
		keyFile, _ := cmd.Flags().GetString("key")
		clientCAFile, _ := cmd.Flags().GetString("client-ca")
		backendCA, _ := cmd.Flags().GetString("backend-ca")
		backendCert, _ := cmd.Flags().GetString("backend-cert")
		backendKey, _ := cmd.Flags().GetString("backend-key")

		var opts []reverseproxy.Option
		if backendCA != "" || backendCert != "" || backendKey != "" {
			pems, err := readPEMFiles(backendCA, backendCert, backendKey)
			if err != nil {
				return err
			}
			opts = append(opts, reverseproxy.WithBackendTLS(reverseproxy.BackendTLSConfig{
				CAPEM:   pems[0],
				CertPEM: pems[1],
				KeyPEM:  pems[2],
			}))
		}

		handler, err := reverseproxy.New(backends, opts...)
		if err != nil {
			return err
		}

		tlsConf, err := newTLSConfig(certFile, keyFile, clientCAFile)
		if err != nil {
			return err
		}

		srv := &http.Server{
			Addr:              address,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       90 * time.Second,
			TLSConfig:         tlsConf,
		}

		slog.Info("reverse proxy listening",
			"address", address,
			"backends", backends,
			"backend_tls", backendCA != "" || backendCert != "" || backendKey != "",
			"tls", tlsConf != nil,
			"mtls", tlsConf != nil && tlsConf.ClientAuth == tls.RequireAndVerifyClientCert,
		)
		if tlsConf != nil {
			return srv.ListenAndServeTLS("", "")
		}
		return srv.ListenAndServe()
	},
}

func init() {
	rootCmd.AddCommand(reverseCmd)
	reverseCmd.Flags().StringP("address", "a", ":8080", "监听地址")
	reverseCmd.Flags().StringSlice("backend", nil, "上游地址，可重复指定实现负载均衡（如 http://127.0.0.1:8080）")
	reverseCmd.Flags().String("cert", "", "服务端 TLS 证书 PEM 文件（与 --key 同时设置启用 TLS 监听）")
	reverseCmd.Flags().String("key", "", "服务端 TLS 私钥 PEM 文件")
	reverseCmd.Flags().String("client-ca", "", "客户端证书签发 CA 的 PEM 文件（在 TLS 基础上启用 mTLS）")
	reverseCmd.Flags().String("backend-ca", "", "校验 backend TLS 证书的 CA PEM 文件（默认信任系统根证书）")
	reverseCmd.Flags().String("backend-cert", "", "与 backend mTLS 时出示的客户端证书 PEM（与 --backend-key 同时设置）")
	reverseCmd.Flags().String("backend-key", "", "与 backend mTLS 时出示的客户端私钥 PEM")
}
