package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// applyConfigFile 把 JSON 配置文件的键值填到命令的 flag 上（键名与
// flag 名一致，如 "address"、"client-ca"）。命令行显式给出的 flag 优先；
// 配置文件只补齐未设置的项。值类型与 flag 对应：
//   - string/duration flag → JSON 字符串（duration 形如 "10s"）
//   - stringSlice/stringArray flag → JSON 字符串数组或逗号分隔字符串
//   - bool flag → JSON 布尔值
//
// 未知键名报错，避免拼写错误被静默忽略。
func applyConfigFile(cmd *cobra.Command, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析配置 %s: %w", path, err)
	}

	flags := cmd.Flags()
	for name, val := range cfg {
		if name == "config" {
			return fmt.Errorf("配置 %s 不支持嵌套 config 字段", path)
		}
		f := flags.Lookup(name)
		if f == nil {
			return fmt.Errorf("配置 %s 含未知字段 %q（键名应与 flag 一致）", path, name)
		}
		if f.Changed {
			continue // 命令行优先
		}
		if val == nil {
			continue
		}
		if err := setFlagValue(f, val); err != nil {
			return fmt.Errorf("配置 %s 的 %q 字段: %w", path, name, err)
		}
	}
	return nil
}

// setFlagValue 按 flag 类型把 JSON 值写进 flag。
func setFlagValue(f *pflag.Flag, val any) error {
	s, isString := val.(string)
	switch f.Value.Type() {
	case "string", "duration":
		if !isString {
			return fmt.Errorf("需要字符串值")
		}
		return f.Value.Set(s)
	case "bool":
		b, ok := val.(bool)
		if !ok {
			return fmt.Errorf("需要布尔值")
		}
		return f.Value.Set(map[bool]string{true: "true", false: "false"}[b])
	case "stringSlice", "stringArray":
		// 数组（元素须为字符串）或逗号分隔字符串
		switch v := val.(type) {
		case string:
			return f.Value.Set(v)
		case []any:
			parts := make([]string, 0, len(v))
			for i, e := range v {
				es, ok := e.(string)
				if !ok {
					return fmt.Errorf("数组元素 %d 不是字符串", i)
				}
				parts = append(parts, es)
			}
			return f.Value.Set(strings.Join(parts, ","))
		default:
			return fmt.Errorf("需要字符串数组")
		}
	default:
		// 数字等其他类型以字符串形式设置（cobra 的数值 flag 接受）
		return f.Value.Set(fmt.Sprint(val))
	}
}

// loadFlagsFromConfig 读取命令的 --config（空则跳过）并应用配置文件。
// 配置文件与命令行参数是**二选一**关系：给了 --config 就不能再显式
// 设置其他 flag（混用直接报错），避免"谁覆盖谁"的歧义；只用配置文件
// 时，文件里缺失的字段落回各 flag 的默认值。
func loadFlagsFromConfig(cmd *cobra.Command) error {
	path, _ := cmd.Flags().GetString("config")
	if path == "" {
		return nil
	}
	if err := rejectFlagMix(cmd.Flags()); err != nil {
		return err
	}
	return applyConfigFile(cmd, path)
}

// rejectFlagMix 报告混用错误：已给 --config 时还显式给出了其他 flag。
func rejectFlagMix(flags *pflag.FlagSet) error {
	var set []string
	flags.Visit(func(f *pflag.Flag) {
		if f.Name != "config" && f.Name != "help" {
			set = append(set, "--"+f.Name)
		}
	})
	if len(set) > 0 {
		return fmt.Errorf("配置文件与命令行参数二选一：同时给出了 %s", strings.Join(set, ", "))
	}
	return nil
}
