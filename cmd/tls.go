package cmd

import (
	"crypto/tls"

	"github.com/Li-giegie/open-proxy/internal/proxycfg"
)

// newTLSConfig 根据证书参数构建服务端 TLS 配置，供各代理命令共用。
// 语义见 proxycfg.ServerTLS。
func newTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	return proxycfg.ServerTLS(certFile, keyFile, clientCAFile)
}

// newClientTLSConfig 根据证书参数构建出站 TLS 客户端配置，供各代理命令
// 以客户端身份访问上游（TLS/mTLS）共用。语义见 proxycfg.ClientTLS。
func newClientTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	return proxycfg.ClientTLS(caFile, certFile, keyFile)
}
