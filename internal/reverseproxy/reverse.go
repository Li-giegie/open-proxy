package reverseproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
)

// ReverseProxy 是 HTTP 反向代理：把请求转发到一组上游，多个上游之间
// 轮询负载均衡，并附加 X-Forwarded-* 头。
//
// 基于 httputil.ReverseProxy 实现，逐跳头处理、WebSocket 升级、
// 流式响应等语义由标准库保证。
type ReverseProxy struct {
	proxy     *httputil.ReverseProxy
	backends  []*url.URL
	next      atomic.Uint64
	transport *http.Transport // WithBackendTLS 设置
}

// Option 自定义反向代理行为，解析失败时返回错误。
type Option func(*ReverseProxy) error

// BackendTLSConfig 描述反向代理作为 TLS 客户端访问 https backend 的
// 配置，字段为 PEM 内容（调用方负责读文件）：
//   - CAPEM 校验 backend 证书（空则信任系统根证书）；
//   - CertPEM/KeyPEM 同时设置时向 backend 出示客户端证书（mTLS）。
type BackendTLSConfig struct {
	CAPEM   []byte
	CertPEM []byte
	KeyPEM  []byte
}

// WithBackendTLS 配置与 backend 通信的 TLS 客户端。
func WithBackendTLS(cfg BackendTLSConfig) Option {
	return func(p *ReverseProxy) error {
		tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}

		if len(cfg.CAPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CAPEM) {
				return errors.New("解析 backend CA 失败")
			}
			tlsConf.RootCAs = pool
		}
		if len(cfg.CertPEM) > 0 || len(cfg.KeyPEM) > 0 {
			if len(cfg.CertPEM) == 0 || len(cfg.KeyPEM) == 0 {
				return errors.New("CertPEM 与 KeyPEM 必须同时设置")
			}
			cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
			if err != nil {
				return fmt.Errorf("解析 backend 客户端证书: %w", err)
			}
			tlsConf.Certificates = []tls.Certificate{cert}
		}

		p.ensureTransport().TLSClientConfig = tlsConf
		return nil
	}
}

// ensureTransport 返回出站 Transport，首次调用时克隆默认实现。
func (p *ReverseProxy) ensureTransport() *http.Transport {
	if p.transport == nil {
		p.transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	return p.transport
}

// New 创建反向代理。backends 为上游地址（如 http://127.0.0.1:8080），
// 至少一个；多个时按轮询分发。opts 可选地配置对 backend 的 TLS。
func New(backends []string, opts ...Option) (*ReverseProxy, error) {
	if len(backends) == 0 {
		return nil, errors.New("至少需要一个 --backend")
	}
	urls := make([]*url.URL, 0, len(backends))
	for _, b := range backends {
		u, err := url.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("解析 backend %q: %w", b, err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("无效的 backend %q（需要形如 http://host:port）", b)
		}
		urls = append(urls, u)
	}

	p := &ReverseProxy{backends: urls}
	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, err
		}
	}

	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			backend := p.backends[int(p.next.Add(1)-1)%len(p.backends)]
			pr.SetURL(backend)
			// 保留客户端的原始 Host 头，便于后端按域名路由
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		// 上游不可达时由默认 ErrorHandler 返回 502
	}
	if p.transport != nil {
		p.proxy.Transport = p.transport
	}
	return p, nil
}

// ServeHTTP 实现 http.Handler。
func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.proxy.ServeHTTP(rw, req)
}
