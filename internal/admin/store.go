package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// 资源类型常量。
const (
	TypeForward = "forward"
	TypeReverse = "reverse"
)

// Resource 是一个受管理的代理资源：类型 + 监听地址 + 完整配置。
// JSON 序列化后持久化到磁盘，管理中心重启后按此恢复。
type Resource struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Type    string       `json:"type"` // forward | reverse
	Address string       `json:"address"`
	Forward *ForwardSpec `json:"forward,omitempty"`
	Reverse *ReverseSpec `json:"reverse,omitempty"`
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
	default:
		return fmt.Errorf("未知资源类型 %q（forward 或 reverse）", r.Type)
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
