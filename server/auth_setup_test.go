package server

import (
	"strings"
	"testing"
)

func TestSetupTokenEqual(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"abc123", "abc123", true},
		{"abc123", "abc124", false},
		{"", "abc123", false},
		{"abc123", "", false},
		{"abc1234", "abc123", false}, // 长度不同直接失败，不走比较
	}
	for _, c := range cases {
		if got := setupTokenEqual(c.got, c.want); got != c.ok {
			t.Errorf("setupTokenEqual(%q,%q)=%v want %v", c.got, c.want, got, c.ok)
		}
	}
}

func TestLoadOrCreateSetupTokenFromEnv(t *testing.T) {
	t.Setenv("ARTEX_SETUP_TOKEN", "  fixed-token  ")
	if got := loadOrCreateSetupToken(); got != "fixed-token" {
		t.Fatalf("应使用环境变量并 trim，得到 %q", got)
	}
}

func TestLoadOrCreateSetupTokenRandom(t *testing.T) {
	t.Setenv("ARTEX_SETUP_TOKEN", "")
	a := loadOrCreateSetupToken()
	b := loadOrCreateSetupToken()
	if len(a) != 32 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("随机口令应为 32 位 hex，得到 %q", a)
	}
	if a == b {
		t.Fatal("两次生成不应相同")
	}
}
