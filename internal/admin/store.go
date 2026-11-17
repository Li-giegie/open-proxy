package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// 资源类型常量。
const (
	TypeForward = "forward"
	TypeReverse = "reverse"
	TypeRelay   = "relay"
	TypeSocks5  = "socks5"
)

// Resource 是一个受管理的代理资源：类型 + 监听地址 + 完整配置。
// JSON 序列化后持久化到磁盘，管理中心重启后按此恢复。
type Resource struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Type    string       `json:"type"` // forward | reverse | relay | socks5
	Address string       `json:"address"`
	Forward *ForwardSpec `json:"forward,omitempty"`
	Reverse *ReverseSpec `json:"reverse,omitempty"`
	Relay   *RelaySpec   `json:"relay,omitempty"`
	Socks5  *Socks5Spec  `json:"socks5,omitempty"`
}

// ForwardSpec 是正向代理资源的配置。认证字段语义与 forward 命令的
// flag 对应；TLS 相关字段为 **PEM 文本内容**（UI 上传文件或粘贴），
// 随资源一起持久化，不再依赖服务端磁盘上的证书文件。零值字段表示
// 不启用对应能力。
type ForwardSpec struct {
	User     string `json:"user"`     // 面向客户端的 Basic 认证（单用户）
	Password string `json:"password"` // 与 user 同时设置
	// Users 是多用户认证集合，可经 API 动态增删（运行中即时生效），
	// 与 User/Password 单用户形式并存，用户名冲突时以 Users 为准。
	Users []StoredUser `json:"users"`
	// 代理链：出站流量经上游代理转发
	Upstream         string `json:"upstream"`
	UpstreamUser     string `json:"upstream_user"`
	UpstreamPassword string `json:"upstream_password"`
	UpstreamCA       string `json:"upstream_ca"`   // 校验 https 上游证书的 CA PEM 内容
	UpstreamCert     string `json:"upstream_cert"` // 对上游 mTLS 出示的证书 PEM 内容
	UpstreamKey      string `json:"upstream_key"`  // 对应私钥 PEM 内容
	// 监听端 TLS（PEM 内容）
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"client_ca"`
}

// StoredUser 是持久化的用户记录。创建时 API 接受 {"user","password"}
// （明文只在请求中存在），落库前转为 salt+hash；密码明文绝不持久化。
type StoredUser struct {
	User     string `json:"user"`
	Password string `json:"password,omitempty"` // 仅创建请求中非空
	Salt     string `json:"salt,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// ReverseSpec 是反向代理资源的配置。backends 语义与 reverse 命令一致，
// TLS 相关字段为 **PEM 文本内容**（UI 上传文件或粘贴，随资源持久化，
// 不依赖服务端磁盘上的证书文件）。
type ReverseSpec struct {
	Backends    []string `json:"backends"`     // 上游地址，多个时轮询负载均衡
	BackendCA   string   `json:"backend_ca"`   // 校验 backend 证书的 CA PEM 内容
	BackendCert string   `json:"backend_cert"` // 对 backend mTLS 出示的证书 PEM 内容
	BackendKey  string   `json:"backend_key"`  // 对应私钥 PEM 内容
	// 监听端 TLS（PEM 内容）
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"client_ca"`
}

// RelaySpec 是 TCP 中继资源的配置。TLS 字段为 **PEM 文本内容**，
// 每个上游可独立配置上游端 TLS；weight 缺省（0 或省略）为 1。
type RelaySpec struct {
	Upstreams []RelayUpstream `json:"upstreams"`
	// DialTimeout/IdleTimeout 为时长字符串（如 "10s"、"2m"），空用默认值。
	DialTimeout string `json:"dial_timeout,omitempty"`
	IdleTimeout string `json:"idle_timeout,omitempty"`
	// 监听端 TLS（PEM 内容）
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"client_ca"`
}

// RelayUpstream 是中继的一个上游。
type RelayUpstream struct {
	Address string `json:"address"`
	Weight  int    `json:"weight,omitempty"` // 缺省 1
	// 上游端 TLS（PEM 内容）：CA 校验上游证书，Cert/Key 对上游 mTLS
	CA   string `json:"ca,omitempty"`
	Cert string `json:"cert,omitempty"`
	Key  string `json:"key,omitempty"`
}

// Socks5Spec 是 SOCKS5 代理资源的配置。认证为 RFC 1929 单用户
// （user/password 成对设置，全空为开放代理）；TLS 字段为 **PEM 文本内容**。
type Socks5Spec struct {
	User     string `json:"user"`
	Password string `json:"password"`
	// 监听端 TLS（PEM 内容）
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	ClientCA string `json:"client_ca"`
}

// validate 校验资源自身完整性（不含证书文件是否存在等构造期检查）。
func (r *Resource) validate() error {
	if r.Name == "" {
		return errors.New("name 不能为空")
	}
	if r.Address == "" {
		return errors.New("address 不能为空")
	}
	switch r.Type {
	case TypeForward:
		if r.Forward == nil {
			return errors.New("forward 资源缺少 forward 配置")
		}
		if (r.Forward.User == "") != (r.Forward.Password == "") {
			return errors.New("user 与 password 必须同时设置")
		}
		if (r.Forward.UpstreamUser == "") != (r.Forward.UpstreamPassword == "") {
			return errors.New("upstream_user 与 upstream_password 必须同时设置")
		}
	case TypeReverse:
		if r.Reverse == nil {
			return errors.New("reverse 资源缺少 reverse 配置")
		}
		if len(r.Reverse.Backends) == 0 {
			return errors.New("backends 不能为空")
		}
	case TypeRelay:
		if r.Relay == nil {
			return errors.New("relay 资源缺少 relay 配置")
		}
		if len(r.Relay.Upstreams) == 0 {
			return errors.New("upstreams 不能为空")
		}
		for i, u := range r.Relay.Upstreams {
			if u.Address == "" {
				return fmt.Errorf("upstreams[%d].address 不能为空", i)
			}
			if u.Weight < 0 {
				return fmt.Errorf("upstreams[%d].weight 必须 >= 0", i)
			}
			if (u.Cert == "") != (u.Key == "") {
				return fmt.Errorf("upstreams[%d] 的 cert 与 key 必须同时设置", i)
			}
		}
		if err := validateDuration(r.Relay.DialTimeout, "dial_timeout"); err != nil {
			return err
		}
		if err := validateDuration(r.Relay.IdleTimeout, "idle_timeout"); err != nil {
			return err
		}
	case TypeSocks5:
		if r.Socks5 == nil {
			return errors.New("socks5 资源缺少 socks5 配置")
		}
		if (r.Socks5.User == "") != (r.Socks5.Password == "") {
			return errors.New("user 与 password 必须同时设置")
		}
	default:
		return fmt.Errorf("未知资源类型 %q（forward / reverse / relay / socks5）", r.Type)
	}
	return nil
}

// validateDuration 校验时长字符串（空为默认值，非空须为正时长）。
func validateDuration(s, field string) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fmt.Errorf("%s %q 不是合法的正时长", field, s)
	}
	return nil
}

// Store 把资源列表持久化为 JSON 文件，写入采用临时文件 + 原子替换，
// 避免中途崩溃留下半截配置。
type Store struct {
	path string
}

// NewStore 创建指向 path 的存储。path 为空时表示不做持久化（仅内存）。
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load 读取已保存的资源列表，文件不存在时返回空列表。
func (s *Store) Load() ([]*Resource, error) {
	if s.path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", s.path, err)
	}
	var res []*Resource
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", s.path, err)
	}
	return res, nil
}

// Save 原子写入资源列表。
func (s *Store) Save(res []*Resource) error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化资源: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入 %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换 %s: %w", s.path, err)
	}
	return nil
}
