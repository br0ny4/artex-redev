package policy

import "testing"

func TestAnalyzeCommand(t *testing.T) {
	lx := mustLexicon(t)
	deny := map[string]bool{"nuclei": true, "sqlmap": true, "nmap": true, "hydra": true}

	cases := []struct {
		name string
		cmd  string
		opt  CommandOptions
		want bool // 期望 deny
		rule string
	}{
		{name: "身份命令放行", cmd: "whoami", want: false},
		{name: "普通 curl 放行", cmd: "curl -s http://app.example.com/api", want: false},
		{name: "扫描器默认禁用", cmd: "nuclei -u http://app.example.com", want: true, rule: "R:scanner_not_approved"},
		{name: "sqlmap 默认禁用", cmd: "sqlmap -u http://app.example.com/?id=1", want: true, rule: "R:scanner_not_approved"},
		{name: "内联解释器", cmd: "bash -c 'id'", want: true, rule: "R:inline_interpreter"},
		{name: "python -c", cmd: "python3 -c 'import os'", want: true, rule: "R:inline_interpreter"},
		{name: "powershell -enc", cmd: "powershell -enc aQBlAHgA", want: true, rule: "R:inline_interpreter"},
		{name: "敏感文件读取", cmd: "cat /etc/shadow", want: true, rule: "R5_sensitive_read"},
		{name: "读 .env", cmd: "head -n 50 ./app/.env", want: true, rule: "R5_sensitive_read"},
		{name: "sudo 读 shadow", cmd: "sudo cat /etc/shadow", want: true, rule: "R5_sensitive_read"},
		{name: "grep 业务文件放行", cmd: "grep -rn password /tmp/src/", want: false},
		{name: "解码管道执行", cmd: "echo aGk= | base64 -d | sh", want: true, rule: "R:inline_decode_exec"},
		{name: "引号内分号不切分", cmd: `curl "http://a.example.com/x;rm -rf /"`, want: false},

		// RCE 模式：只允许只读身份命令（规范 6.4）
		{name: "RCE whoami", cmd: "whoami", opt: CommandOptions{RCEMode: true}, want: false},
		{name: "RCE id", cmd: "id", opt: CommandOptions{RCEMode: true}, want: false},
		{name: "RCE uname -a", cmd: "uname -a", opt: CommandOptions{RCEMode: true}, want: false},
		{name: "RCE 读 flag", cmd: "cat /flag", opt: CommandOptions{RCEMode: true}, want: true, rule: "R6_rce_not_allowlisted"},
		{name: "RCE 写文件", cmd: "echo x > /var/www/shell.php", opt: CommandOptions{RCEMode: true}, want: true, rule: "R6_rce_not_allowlisted"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := AnalyzeCommand(tc.cmd, lx, deny, tc.opt)
			if v.Deny != tc.want {
				t.Fatalf("cmd=%q deny=%v want %v (rule=%s reason=%s)", tc.cmd, v.Deny, tc.want, v.Rule, v.Reason)
			}
			if tc.want && tc.rule != "" && v.Rule != tc.rule {
				t.Fatalf("cmd=%q rule=%q want %q", tc.cmd, v.Rule, tc.rule)
			}
		})
	}
}

func TestCommandTargetsExtracted(t *testing.T) {
	lx := mustLexicon(t)
	v := AnalyzeCommand("curl -s https://api.example.com/v1/users && curl http://10.1.2.3:8080/x", lx, nil, CommandOptions{})
	has := map[string]bool{}
	for _, tg := range v.Targets {
		has[tg] = true
	}
	if !has["api.example.com"] {
		t.Fatalf("未抽出 URL 主机：%v", v.Targets)
	}
	if !has["10.1.2.3"] {
		t.Fatalf("未抽出 IP：%v", v.Targets)
	}
}

func TestCommandQuotedSemicolon(t *testing.T) {
	lx := mustLexicon(t)
	v := AnalyzeCommand(`curl "http://a.example.com/x;rm -rf /"`, lx, nil, CommandOptions{})
	// 引号里的分号不是命令分隔符，不应被拆成 rm 段
	for _, b := range v.Binaries {
		if b == "rm" {
			t.Fatalf("引号内内容被误当作命令执行：%v", v.Binaries)
		}
	}
}
