// Package proxycfg 集中代理配置的构造逻辑：TLS（服务端/客户端）与
// 上游代理 URL 解析。命令行（cmd）与管理中心（internal/admin）共用，
// 保证两处的校验规则一致。
//
// TLS 配置有两层入口：内容版（*FromPEM，直接给 PEM 字节，管理中心
// 上传/粘贴走这里）与路径版（读文件后委托内容版，CLI flag 走这里）。
package proxycfg

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
)

// ServerTLS 根据证书文件路径构建服务端 TLS 监听配置，语义同
// ServerTLSFromPEM。路径为空表示不设置。
func ServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	pems, err := readPEMs(certFile, keyFile, clientCAFile)
	if err != nil {
		return nil, err
	}
	return ServerTLSFromPEM(pems[0], pems[1], pems[2])
}

// ServerTLSFromPEM 根据证书内容构建服务端 TLS 监听配置。
//   - certPEM/keyPEM 均非空时启用 TLS 监听；
//   - 另有 clientCAPEM 时升级为 mTLS：强制客户端出示由该 CA 签发的
//     证书，否则握手失败；
//   - 三者均为空时返回 nil（明文监听）。
func ServerTLSFromPEM(certPEM, keyPEM, clientCAPEM []byte) (*tls.Config, error) {
	if len(certPEM) == 0 && len(keyPEM) == 0 && len(clientCAPEM) == 0 {
		return nil, nil
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, errors.New("cert 与 key 必须同时设置（client-ca 也依赖它们）")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析服务端证书: %w", err)
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if len(clientCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(clientCAPEM) {
			return nil, errors.New("解析客户端 CA 失败")
		}
		conf.ClientCAs = pool
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return conf, nil
}

// ClientTLS 根据证书文件路径构建出站 TLS 客户端配置，语义同
// ClientTLSFromPEM。路径为空表示不设置。
func ClientTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	pems, err := readPEMs(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return ClientTLSFromPEM(pems[0], pems[1], pems[2])
}

// ClientTLSFromPEM 根据证书内容构建出站 TLS 客户端配置，用于以
// 客户端身份访问上游：
//   - caPEM 非空时用于校验对端证书（空则信任系统根证书）；
//   - certPEM/keyPEM 同时非空时向对端出示客户端证书（mTLS）；
//   - 三者均为空时返回 nil（调用方以默认配置直连）。
func ClientTLSFromPEM(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	if len(caPEM) == 0 && len(certPEM) == 0 && len(keyPEM) == 0 {
		return nil, nil
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12}

	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("解析 CA 失败")
		}
		conf.RootCAs = pool
	}

	if len(certPEM) > 0 || len(keyPEM) > 0 {
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			return nil, errors.New("cert 与 key 必须同时设置")
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("解析客户端证书: %w", err)
		}
		conf.Certificates = []tls.Certificate{cert}
	}

	return conf, nil
}

// UpstreamURL 构造上游代理 URL（代理链）。raw 为空返回 nil（不启用
// 代理链）；user/password 非空时作为对上游的 Basic 认证凭证，不能与
// raw 中自带的 userinfo 同时使用（避免两处凭证打架）。
func UpstreamURL(raw, user, password string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("解析 upstream %q: %w", raw, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("无效的 upstream %q（需要形如 http://host:port 或 https://host:port）", raw)
	}
	if user != "" || password != "" {
		if user == "" || password == "" {
			return nil, errors.New("upstream-user 与 upstream-password 必须同时设置")
		}
		if u.User != nil {
			return nil, errors.New("upstream-user/upstream-password 不能与 upstream URL 中的 userinfo 同时使用")
		}
		u.User = url.UserPassword(user, password)
	}
	return u, nil
}

// readPEMs 逐个读取 PEM 文件，空路径返回 nil。
func readPEMs(paths ...string) ([][]byte, error) {
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
