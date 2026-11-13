package cmd

import (
	"testing"
)

// TestBuildUpstreamURL 验证代理链上游 URL 的构造与校验：
// 独立 flag 凭证、URL userinfo 凭证、两者冲突与参数校验。
func TestBuildUpstreamURL(t *testing.T) {
	// 不设置：无代理链
	u, err := buildUpstreamURL("", "", "")
	if err != nil || u != nil {
		t.Errorf("empty: u=%v err=%v, want nil/nil", u, err)
	}

	// 纯地址
	u, err = buildUpstreamURL("http://127.0.0.1:1080", "", "")
	if err != nil || u.User != nil || u.Host != "127.0.0.1:1080" {
		t.Errorf("plain: u=%v err=%v", u, err)
	}

	// URL 自带 userinfo
	u, err = buildUpstreamURL("http://u:p@127.0.0.1:1080", "", "")
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if got, _ := u.User.Password(); u.User.Username() != "u" || got != "p" {
		t.Errorf("userinfo = %q/%q, want u/p", u.User.Username(), got)
	}

	// 独立 flag 凭证（密码含特殊字符，URL 写法需要百分号编码）
	u, err = buildUpstreamURL("https://proxy.example.com:8443", "alice", "p@ss:w/ord")
	if err != nil {
		t.Fatalf("flags: %v", err)
	}
	if got, _ := u.User.Password(); u.User.Username() != "alice" || got != "p@ss:w/ord" {
		t.Errorf("flags userinfo = %q/%q, want alice/p@ss:w/ord", u.User.Username(), got)
	}

	// 只给用户名
	if _, err := buildUpstreamURL("http://127.0.0.1:1080", "u", ""); err == nil {
		t.Errorf("user only: want error")
	}
	// 只给密码
	if _, err := buildUpstreamURL("http://127.0.0.1:1080", "", "p"); err == nil {
		t.Errorf("password only: want error")
	}
	// flag 与 URL userinfo 冲突
	if _, err := buildUpstreamURL("http://u:p@127.0.0.1:1080", "a", "b"); err == nil {
		t.Errorf("conflict: want error")
	}
	// 非法 scheme
	if _, err := buildUpstreamURL("socks5://127.0.0.1:1080", "", ""); err == nil {
		t.Errorf("bad scheme: want error")
	}
	// 缺 host
	if _, err := buildUpstreamURL("http://", "", ""); err == nil {
		t.Errorf("no host: want error")
	}
}
