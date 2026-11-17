package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"strings"

	"github.com/spf13/cobra"
)

// newTestCmd 构造带常用类型 flag 的测试命令。
func newTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "test", RunE: func(*cobra.Command, []string) error { return nil }}
	c.Flags().StringP("config", "c", "", "")
	c.Flags().String("address", ":1080", "")
	c.Flags().String("cert", "", "")
	c.Flags().Duration("dial-timeout", 10*time.Second, "")
	c.Flags().StringSlice("backend", nil, "")
	c.Flags().StringArray("upstream", nil, "")
	c.Flags().Bool("verbose", false, "")
	return c
}

// writeCfg 写临时 JSON 配置。
func writeCfg(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyConfigFile(t *testing.T) {
	c := newTestCmd()
	path := writeCfg(t, `{
		"address": "127.0.0.1:19080",
		"cert": "certs/server.pem",
		"dial-timeout": "5s",
		"backend": ["http://127.0.0.1:9000", "http://127.0.0.1:9001"],
		"upstream": "10.0.0.1:9001=3"
	}`)
	if err := applyConfigFile(c, path); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Flags().GetString("address"); v != "127.0.0.1:19080" {
		t.Errorf("address = %q", v)
	}
	if v, _ := c.Flags().GetString("cert"); v != "certs/server.pem" {
		t.Errorf("cert = %q", v)
	}
	if v, _ := c.Flags().GetDuration("dial-timeout"); v != 5*time.Second {
		t.Errorf("dial-timeout = %v", v)
	}
	if v, _ := c.Flags().GetStringSlice("backend"); len(v) != 2 || v[0] != "http://127.0.0.1:9000" {
		t.Errorf("backend = %v", v)
	}
	if v, _ := c.Flags().GetStringArray("upstream"); len(v) != 1 || v[0] != "10.0.0.1:9001=3" {
		t.Errorf("upstream = %v", v)
	}
}

// TestApplyConfigCommandLineMixRejected 验证二选一：--config 与其他
// 显式 flag 混用直接报错。
func TestApplyConfigCommandLineMixRejected(t *testing.T) {
	c := newTestCmd()
	// --config 本身先设置（模拟命令行传了 -c）
	if err := c.Flags().Set("config", "some.json"); err != nil {
		t.Fatal(err)
	}
	if err := c.Flags().Set("address", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	err := loadFlagsFromConfig(c)
	if err == nil {
		t.Fatalf("want mix error")
	}
	if !strings.Contains(err.Error(), "二选一") {
		t.Errorf("err = %q, want 含 \"二选一\"", err)
	}
}

// TestApplyConfigFileErrors 覆盖错误路径：未知字段、类型不匹配、
// 非法 JSON、文件不存在、嵌套 config。
func TestApplyConfigFileErrors(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"未知字段", `{"no-such-flag": "x"}`},
		{"string 传数字", `{"cert": 123}`},
		{"duration 传数字", `{"dial-timeout": 10}`},
		{"bool 传字符串", `{"verbose": "yes"}`},
		{"数组元素非字符串", `{"backend": [1, 2]}`},
		{"嵌套 config", `{"config": "x.json"}`},
		{"非法 JSON", `{not json`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := newTestCmd()
			path := writeCfg(t, c.body)
			if err := applyConfigFile(cmd, path); err == nil {
				t.Errorf("want error")
			}
		})
	}
	if err := applyConfigFile(newTestCmd(), filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Errorf("absent file: want error")
	}
}
