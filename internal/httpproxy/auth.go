package httpproxy

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Authenticator 是代理认证接口，校验通过代理的请求。
// 通过实现该接口可扩展 IP 白名单、Token 等校验方式；nil 表示不认证。
type Authenticator interface {
	// Authenticate 校验请求携带的凭证，返回是否放行。
	Authenticate(req *http.Request) bool
	// Challenge 返回 407 响应中 Proxy-Authenticate 头的值
	// （如 `Basic realm="..."`），告知客户端应如何提供凭证。
	Challenge() string
}

// Credentials 实现 Authenticator：标准 HTTP Basic 代理认证，
// 凭据经 Proxy-Authorization 头传递。
type Credentials struct {
	Username string
	Password string
}

// Authenticate 校验 Proxy-Authorization 是否匹配凭据。
// 用户名与密码均使用恒定时间比较，避免时序侧信道。
func (c *Credentials) Authenticate(req *http.Request) bool {
	username, password, ok := basicCredentials(req)
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(c.Username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(c.Password)) == 1
	return userOK && passOK
}

// Challenge 返回 Basic 认证的挑战头。
func (c *Credentials) Challenge() string {
	return `Basic realm="open-proxy", charset="UTF-8"`
}

// User 返回已认证用户的用户名（Authenticate 通过后即为 c.Username），
// 供 Metrics 归属统计。实现该可选方法即可被 Proxy 识别。
func (c *Credentials) User(*http.Request) string {
	return c.Username
}

// userEntry 是一条用户记录：密码以 salt+SHA-256 摘要存储，明文不落盘。
type userEntry struct {
	salt string
	hash string
}

// UserStore 是可动态增删用户的认证存储，实现 Authenticator。
// 增删立即生效，无需重建代理；空用户集合拒绝所有请求。
type UserStore struct {
	mu    sync.RWMutex
	users map[string]userEntry
}

// NewUserStore 创建空的用户存储。
func NewUserStore() *UserStore {
	return &UserStore{users: map[string]userEntry{}}
}

// Add 添加或覆盖一个用户，密码以随机 salt+SHA-256 存储。
func (s *UserStore) Add(user, password string) error {
	if user == "" {
		return errors.New("用户名不能为空")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("生成 salt: %w", err)
	}
	entry := userEntry{
		salt: hex.EncodeToString(salt),
		hash: hashPassword(salt, password),
	}
	s.mu.Lock()
	s.users[user] = entry
	s.mu.Unlock()
	return nil
}

// Remove 删除用户，返回是否存在。
func (s *UserStore) Remove(user string) bool {
	s.mu.Lock()
	_, ok := s.users[user]
	delete(s.users, user)
	s.mu.Unlock()
	return ok
}

// Users 返回全部用户名（按字典序）。
func (s *UserStore) Users() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.users))
	for name := range s.users {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AddStored 按 salt+hash 恢复一条持久化的用户记录（不重新计算摘要）。
func (s *UserStore) AddStored(user, salt, hash string) {
	s.mu.Lock()
	s.users[user] = userEntry{salt: salt, hash: hash}
	s.mu.Unlock()
}

// StoredDigest 返回用户当前的 salt 与摘要（供持久化），不存在时 ok 为 false。
func (s *UserStore) StoredDigest(user string) (salt, hash string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, exists := s.users[user]
	return entry.salt, entry.hash, exists
}

// Authenticate 校验 Proxy-Authorization 是否匹配某个用户的密码。
func (s *UserStore) Authenticate(req *http.Request) bool {
	user, password, ok := basicCredentials(req)
	if !ok {
		return false
	}
	s.mu.RLock()
	entry, exists := s.users[user]
	s.mu.RUnlock()
	if !exists {
		return false
	}
	salt, _ := hex.DecodeString(entry.salt)
	return subtle.ConstantTimeCompare(
		[]byte(entry.hash), []byte(hashPassword(salt, password))) == 1
}

// Challenge 返回 Basic 认证的挑战头。
func (s *UserStore) Challenge() string {
	return `Basic realm="open-proxy", charset="UTF-8"`
}

// User 返回请求凭据中的用户名（Authenticate 通过后调用），
// 供 Metrics 归属统计。
func (s *UserStore) User(req *http.Request) string {
	user, _, ok := basicCredentials(req)
	if !ok {
		return ""
	}
	return user
}

// basicCredentials 解析 Proxy-Authorization 中的 Basic 凭据。
func basicCredentials(req *http.Request) (user, password string, ok bool) {
	const scheme = "Basic "
	auth := req.Header.Get("Proxy-Authorization")
	if len(auth) <= len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return "", "", false
	}
	payload, err := base64.StdEncoding.DecodeString(auth[len(scheme):])
	if err != nil {
		return "", "", false
	}
	user, password, ok = strings.Cut(string(payload), ":")
	return user, password, ok
}

// hashPassword 计算 hex(salt || password) 的 SHA-256。
func hashPassword(salt []byte, password string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}
