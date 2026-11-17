package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// TLSSettings 是证书文件路径三元组。监听端语义见 netutil.ServerTLS
// （cert+key 启用 TLS，再加 client_ca 升级 mTLS）；上游端语义见
// netutil.ClientTLS（ca 校验上游证书，cert+key 对上游 mTLS 出示
// 客户端证书）。全空表示明文。
type TLSSettings struct {
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"client_ca"`
}

// ClientTLSSettings 是上游端 TLS 的证书路径三元组，字段名与对端角色
// 对应：CA 校验上游，Cert/Key 是本端作为客户端出示的 mTLS 证书。
type ClientTLSSettings struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// UpstreamConfig 是一个上游：地址、选择权重与可选的 TLS 配置。
type UpstreamConfig struct {
	Address string             `json:"address"`
	Weight  int                `json:"weight"`
	TLS     *ClientTLSSettings `json:"tls"`
}

// Config 是中继的完整配置（JSON 格式），示例见 configs/relay.example.json。
type Config struct {
	// Listen 为本地监听地址。
	Listen string `json:"listen"`
	// ListenTLS 为监听端 TLS/mTLS 配置，nil 表示明文监听。
	ListenTLS *TLSSettings `json:"listen_tls"`
	// Upstreams 为上游列表，至少一个。
	Upstreams []UpstreamConfig `json:"upstreams"`
	// DialTimeout 为连接上游的超时时间，缺省 10s。
	DialTimeout string `json:"dial_timeout"`
	// IdleTimeout 为透传阶段单方向无数据的超时时间，缺省 2m。
	IdleTimeout string `json:"idle_timeout"`
}

const (
	defaultDialTimeout = 10 * time.Second
	defaultIdleTimeout = 2 * time.Minute
)

// Load 从 JSON 文件读取并校验配置。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置 %s 无效: %w", path, err)
	}
	return &cfg, nil
}

// Validate 校验配置的必要字段与取值范围。
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen 不能为空")
	}
	if len(c.Upstreams) == 0 {
		return errors.New("至少需要一个 upstream")
	}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Address == "" {
			return fmt.Errorf("upstreams[%d].address 不能为空", i)
		}
		if u.Weight < 1 {
			return fmt.Errorf("upstreams[%d].weight 必须 >= 1", i)
		}
		t := u.TLS
		if t != nil && (t.Cert == "") != (t.Key == "") {
			return fmt.Errorf("upstreams[%d].tls 的 cert 与 key 必须同时设置", i)
		}
	}
	if c.ListenTLS != nil && (c.ListenTLS.Cert == "") != (c.ListenTLS.Key == "") {
		return errors.New("listen_tls 的 cert 与 key 必须同时设置")
	}
	if _, err := c.dialTimeout(); err != nil {
		return err
	}
	if _, err := c.idleTimeout(); err != nil {
		return err
	}
	return nil
}

// dialTimeout 解析拨号超时，空值用默认值。
func (c *Config) dialTimeout() (time.Duration, error) {
	if c.DialTimeout == "" {
		return defaultDialTimeout, nil
	}
	d, err := time.ParseDuration(c.DialTimeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("dial_timeout %q 不是合法的正时长", c.DialTimeout)
	}
	return d, nil
}

// idleTimeout 解析空闲超时，空值用默认值。
func (c *Config) idleTimeout() (time.Duration, error) {
	if c.IdleTimeout == "" {
		return defaultIdleTimeout, nil
	}
	d, err := time.ParseDuration(c.IdleTimeout)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("idle_timeout %q 不是合法的正时长", c.IdleTimeout)
	}
	return d, nil
}
