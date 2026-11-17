package socks5

import (
	"crypto/subtle"
)

// Authenticator 是代理认证接口，校验 SOCKS5 用户名/密码子协商
// （RFC 1929）提交的凭证。通过实现该接口可扩展 IP 白名单、Token 等
// 校验方式；nil 表示开放代理（不认证）。
type Authenticator interface {
	// Authenticate 校验子协商请求携带的用户名与密码，返回是否放行。
	Authenticate(username, password string) bool
}

// Credentials 实现 Authenticator：单用户名/密码认证，
// 用户名与密码均使用恒定时间比较，避免时序侧信道
// （与 internal/httpproxy 的 Credentials 做法一致）。
type Credentials struct {
	Username string
	Password string
}

// Authenticate 校验用户名与密码是否匹配。
func (c *Credentials) Authenticate(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(c.Username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(c.Password)) == 1
	return userOK && passOK
}
