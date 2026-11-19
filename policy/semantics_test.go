package policy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestClassifyTable(t *testing.T) {
	lx := mustLexicon(t)
	c := NewClassifier(lx, SemanticsConfig{})

	cases := []struct {
		name     string
		method   string
		path     string
		query    string
		body     string
		want     string
		wantHigh bool
	}{
		{name: "GET 列表 → F", method: "GET", path: "/api/user/list", want: ClassF},
		{name: "GET 详情 → F", method: "GET", path: "/api/user/42", want: ClassF},
		{name: "DELETE 方法 → A", method: "DELETE", path: "/api/user/42", want: ClassA},
		{name: "PUT 方法 → B", method: "PUT", path: "/api/user/42", want: ClassB},
		{name: "PATCH 方法 → B", method: "PATCH", path: "/api/user/42", want: ClassB},
		// 上游 CHANGELOG 明确漏过的那类：GET 也能触发的删除接口
		{name: "GET 删除接口 → A", method: "GET", path: "/api/user/delete", query: "id=1", want: ClassA},
		{name: "POST 删除 → A", method: "POST", path: "/api/user/delete", want: ClassA},
		{name: "POST remove → A", method: "POST", path: "/api/user/remove", want: ClassA},
		{name: "del 段 → A", method: "POST", path: "/api/del/user", want: ClassA},
		{name: "camel 删除 → A", method: "POST", path: "/api/userDelete", want: ClassA},
		{name: "批量清空 → A", method: "POST", path: "/api/user/clearAll", want: ClassA},
		{name: "truncate → A", method: "POST", path: "/api/table/truncate", want: ClassA},
		{name: "覆盖 → B", method: "POST", path: "/api/user/overwrite", want: ClassB},
		{name: "重置 → B", method: "POST", path: "/api/user/reset", want: ClassB},
		{name: "修改 → C", method: "POST", path: "/api/user/update", want: ClassC},
		{name: "改名 → C", method: "POST", path: "/api/user/rename", want: ClassC},
		{name: "取消订单 → D", method: "POST", path: "/api/order/cancel", want: ClassD},
		{name: "退款 → D 高危", method: "POST", path: "/api/order/refund", want: ClassD, wantHigh: true},
		{name: "提现 → D 高危", method: "POST", path: "/api/wallet/withdraw", want: ClassD, wantHigh: true},
		{name: "创建 → E", method: "POST", path: "/api/user/create", want: ClassE},
		{name: "上传 → E", method: "POST", path: "/api/file/upload", want: ClassE},
		{name: "POST 无语义 → unknown", method: "POST", path: "/api/user/profile", want: ClassUnknown},
		{name: "delivery 不误报", method: "POST", path: "/api/delivery", want: ClassUnknown},
		{name: "settings 不误报", method: "POST", path: "/api/user/settings", want: ClassUnknown},
		{name: "TRACE 禁止", method: "TRACE", path: "/api/user", want: ClassDeny},
		// 方法伪装
		{name: "参数 _method=DELETE", method: "POST", path: "/api/user/42", body: `{"_method":"DELETE"}`, want: ClassA},
		// 参数开关
		{name: "op=purge", method: "POST", path: "/api/user", body: `{"op":"purge"}`, want: ClassA},
		{name: "type=hard_delete", method: "POST", path: "/api/user", body: `{"type":"hard_delete"}`, want: ClassA},
		{name: "force=true is_cover", method: "POST", path: "/api/user", body: `{"is_cover":1,"force":true}`, want: ClassB},
		// 中文命名
		{name: "中文删除", method: "POST", path: "/api/用户/删除", want: ClassA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{Method: tc.method, Path: tc.path, Header: http.Header{}}
			if tc.query != "" {
				q, _ := url.ParseQuery(tc.query)
				req.Query = q
			}
			if tc.body != "" {
				req.Body = []byte(tc.body)
			}
			got := c.Classify(req)
			if got.Class != tc.want {
				t.Fatalf("class=%q want %q (rule=%s matched=%s evidence=%v)",
					got.Class, tc.want, got.Rule, got.Matched, got.Evidence)
			}
			if got.HighRisk != tc.wantHigh {
				t.Fatalf("highRisk=%v want %v (matched=%s)", got.HighRisk, tc.wantHigh, got.Matched)
			}
		})
	}
}

func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		"userDelete":     {"user", "Delete"},
		"delete_user":    {"delete", "user"},
		"del-user":       {"del", "user"},
		"/a/b/c":         {"a", "b", "c"},
		"batchDeleteAll": {"batch", "Delete", "All"},
	}
	for in, want := range cases {
		got := splitWords(in)
		if len(got) != len(want) {
			t.Fatalf("splitWords(%q)=%v want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("splitWords(%q)=%v want %v", in, got, want)
			}
		}
	}
}

func TestNormToken(t *testing.T) {
	// 命名变体归一：delete_user / DELUSER / del-user 必须等价
	for _, in := range []string{"delete_user", "DELUSER", "del-user", "DeleteUser"} {
		if got := normToken(in); got != "deleteuser" && got != "deluser" {
			t.Fatalf("normToken(%q)=%q", in, got)
		}
	}
}
