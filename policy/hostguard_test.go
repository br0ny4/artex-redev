package policy

import (
	"strings"
	"testing"
	"time"
)

// 宿主机边界：离线/本地分析域"只守宿主机"的行为约定。
//
// 这几条用例就是域包 yaml 里 host_boundary 的验收：
//   - 打坏本机/把不可信代码放上宿主机 → 始终拒（与是否离线无关）；
//   - 分析工作里的正常动作（python -c 做计算、样本里出现 shadow 字样、连本机辅助服务）
//     → 离线域放行，不再高频打断；
//   - 越权读取宿主机凭据 → 仍拒。
func TestHostBoundaryOfflineRelaxations(t *testing.T) {
	lx := mustLexicon(t)
	offline := CommandOptions{
		AllowInlineInterp: true,
		AllowLoopback:     true,
		AuthorizedPaths:   []string{"/srv/triage/samples/inbox", "/srv/audit/gateway"},
	}
	cases := []struct {
		name string
		cmd  string
		opt  CommandOptions
		deny bool
		rule string
	}{
		// —— 离线域放行的分析动作 ——
		{name: "python -c 一次性计算", cmd: `python3 -c "import hashlib;print(hashlib.sha256(b'x').hexdigest())"`, opt: offline, deny: false},
		{name: "bash -c 只读管道", cmd: `bash -c "rabin2 -zz ./a.bin | head -50"`, opt: offline, deny: false},
		{name: "样本内字符串命中 shadow", cmd: `strings ./a.bin | grep -i shadow`, opt: offline, deny: false},
		{name: "搜样本目录里的 shadow 字样", cmd: `grep -rn shadow /srv/triage/samples/inbox/`, opt: offline, deny: false},
		{name: "清理临时产物", cmd: `rm -rf /tmp/artex-work ./out`, opt: offline, deny: false},
		{name: "dd 写黑洞", cmd: `dd if=./a.bin of=/dev/null bs=1M`, opt: offline, deny: false},
		{name: "普通改产物目录权限", cmd: `chmod -R 755 /tmp/artex-out`, opt: offline, deny: false},
		{name: "读授权目录内样本", cmd: `xxd /srv/triage/samples/inbox/a.bin | head`, opt: offline, deny: false},

		// —— 宿主机边界：始终拒 ——
		{name: "删根", cmd: `rm -rf /`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "删根通配", cmd: `rm -rf /*`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "删系统目录", cmd: `rm -rf /etc`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "写块设备", cmd: `dd if=/dev/zero of=/dev/sda bs=1M`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "格式化", cmd: `mkfs.ext4 /dev/sda1`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "关机", cmd: `shutdown -h now`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "递归改根权限", cmd: `chmod -R 777 /`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "内联载荷删根", cmd: `python3 -c "import os; os.system('rm -rf /')"`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "内联载荷读 shadow", cmd: `bash -c "cat /etc/shadow"`, opt: offline, deny: true, rule: RuleHostDestructive},
		{name: "读宿主机私钥", cmd: `cat ~/.ssh/id_rsa`, opt: offline, deny: true, rule: "R5_sensitive_read"},

		// —— 直接执行授权目录内的文件：默认拒（local_paths 是"可读"不是"可执行"）——
		{name: "执行样本", cmd: `cd /srv/triage/samples/inbox && ./a.bin`, opt: offline, deny: true, rule: RuleHostExecScoped},
		{name: "绝对路径执行样本", cmd: `/srv/triage/samples/inbox/a.bin --help`, opt: offline, deny: true, rule: RuleHostExecScoped},
		{name: "解释器跑授权目录脚本", cmd: `bash /srv/audit/gateway/build.sh`, opt: offline, deny: true, rule: RuleHostExecScoped},
		{name: "解释器跑分析脚本（授权目录外）", cmd: `python3 /tmp/analyze.py ./a.bin`, opt: offline, deny: false},

		// —— 在线域：内联解释器仍拒（规范 6.4）——
		{name: "在线域 python -c 仍拒", cmd: `python3 -c "print(1)"`, opt: CommandOptions{}, deny: true, rule: "R:inline_interpreter"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := AnalyzeCommand(tc.cmd, lx, nil, tc.opt)
			if v.Deny != tc.deny {
				t.Fatalf("cmd=%q deny=%v want %v（rule=%s reason=%s）", tc.cmd, v.Deny, tc.deny, v.Rule, v.Reason)
			}
			if tc.deny && tc.rule != "" && v.Rule != tc.rule {
				t.Fatalf("cmd=%q rule=%q want %q", tc.cmd, v.Rule, tc.rule)
			}
		})
	}
}

// 显式允许后，"执行授权目录内文件"放行——域包可以用 allow_executing_scoped_files 打开，
// 但要先知道自己在做什么。
func TestHostBoundaryAllowScopedExecution(t *testing.T) {
	lx := mustLexicon(t)
	opt := CommandOptions{AuthorizedPaths: []string{"/srv/audit/gateway"}, AllowExecuteScoped: true}
	if v := AnalyzeCommand(`bash /srv/audit/gateway/build.sh`, lx, nil, opt); v.Deny {
		t.Fatalf("显式允许后不应拦：%s", v.Reason)
	}
}

// 引擎层：域包决定宽松度，未声明时按在线域最严。
func TestEngineHostBoundaryByPack(t *testing.T) {
	offlineCfg, err := PackConfig("binary-re")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	eng := &Engagement{
		ID: "HOST-BOUNDARY-TEST", Client: "internal",
		Window: Window{StartsAt: now.Add(-time.Hour).Format(time.RFC3339), EndsAt: now.Add(time.Hour).Format(time.RFC3339)},
		Scope:  EngScope{LocalPaths: []string{"/srv/triage/samples/inbox"}},
	}
	e, err := New(offlineCfg, nil, eng, NewNetResolver(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Offline() {
		t.Fatal("binary-re 应按离线域运行")
	}
	allowed := []string{
		`python3 -c "print(1)"`,                // 离线放宽内联解释器
		`curl -s http://127.0.0.1:8080/health`, // 离线放行回环
		`strings /srv/triage/samples/inbox/a.bin | grep -i shadow`,
	}
	for _, cmd := range allowed {
		if d := e.CheckCommand("t", cmd, CommandOptions{}); d.Action != ActionAllow {
			t.Fatalf("离线域应放行 %q，实际 %s：%s", cmd, d.Action, d.Reason)
		}
	}
	denied := []string{
		`rm -rf /`,
		`/srv/triage/samples/inbox/a.bin`,
		`curl -s http://evil.example.net/x`,
	}
	for _, cmd := range denied {
		if d := e.CheckCommand("t", cmd, CommandOptions{}); d.Action != ActionDeny {
			t.Fatalf("离线域应拦住 %q，实际 %s", cmd, d.Action)
		}
	}

	// 在线域：同一台机器、同一批命令，内联解释器与回环仍按作业边界处理。
	onlineCfg, err := PackConfig("web-pentest")
	if err != nil {
		t.Fatal(err)
	}
	oe, err := New(onlineCfg, nil, eng, NewNetResolver(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if oe.Offline() {
		t.Fatal("web-pentest 应是在线域")
	}
	d := oe.CheckCommand("t", `python3 -c "print(1)"`, CommandOptions{})
	if d.Action != ActionDeny || !strings.Contains(d.Reason, "内联解释器") {
		t.Fatalf("在线域应拒内联解释器，实际 %s：%s", d.Action, d.Reason)
	}
}
