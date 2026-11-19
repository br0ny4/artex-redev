package policy

import (
	"net"
	"net/url"
	"path"
	"strings"
)

// CommandOptions 控制命令判定模式。
//
// RCEMode：命令是在目标上执行（webshell / 命令注入验证），按规范 6.4 只允许
// 只读身份命令。普通模式（本地沙箱里的 Bash）不套这条——那是操作者自己的机器。
type CommandOptions struct {
	RCEMode bool
}

// CommandVerdict 是命令判定结果。
type CommandVerdict struct {
	Deny     bool
	Rule     string
	Reason   string
	Binaries []string
	Targets  []string // 命令里出现的 URL / host / IP，供范围校验
}

// 内联解释器：`bash -c`、`python -c` 之类可以把任意逻辑藏进一个参数，
// 静态判定看不到真实动作，一律拒绝（规范第三章 1、6.4）。
var inlineInterpFlags = map[string][]string{
	"sh":         {"-c"},
	"bash":       {"-c"},
	"zsh":        {"-c"},
	"dash":       {"-c"},
	"cmd":        {"/c", "/C"},
	"cmd.exe":    {"/c", "/C"},
	"powershell": {"-c", "-command", "-enc", "-encodedcommand"},
	"pwsh":       {"-c", "-command", "-enc", "-encodedcommand"},
	"python":     {"-c"},
	"python3":    {"-c"},
	"perl":       {"-e"},
	"ruby":       {"-e"},
	"node":       {"-e", "--eval"},
	"php":        {"-r"},
}

// 敏感读取目标：命中即停（规范 5.4）。
var sensitivePathTokens = []string{
	"/etc/shadow", "/etc/passwd", "/etc/sudoers",
	"id_rsa", "id_ed25519", ".ssh/", "authorized_keys",
	".env", "application.yml", "application.yaml", "application.properties",
	"web.xml", "wp-config.php", "config.php", "settings.py",
	"credentials", ".aws/", ".kube/config", "jwt.key",
	"shadow", "master.key", "secret_key",
}

// decodeBinaries 是会把编码内容还原成可执行文本的程序，管道进 shell 时一律拒绝。
var decodeBinaries = map[string]bool{
	"base64": true, "xxd": true, "openssl": true, "rev": true, "uudecode": true,
}

// readBinaries 是会读取文件内容的程序：只有它们命中敏感路径才算违规，
// 否则 `grep xxx /etc/shadow` 这种参数也会被误判。
var readBinaries = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true,
	"nl": true, "strings": true, "grep": true, "egrep": true, "fgrep": true,
	"awk": true, "sed": true, "cut": true, "base64": true, "xxd": true,
	"od": true, "hexdump": true, "tac": true, "vim": true, "vi": true, "nano": true,
}

// CopyOrExfil 是可能把数据带出/写出的程序，配合敏感路径判定（规范红线 8）。
var copyOrExfil = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true,
	"scp": true, "rsync": true, "ftp": true, "sftp": true, "ssh": true,
}

// AnalyzeCommand 做规范第三章 / 6.4 的命令判定。返回 Deny=true 时应阻断。
func AnalyzeCommand(cmd string, lex *Lexicon, denyBinaries map[string]bool, opt CommandOptions) CommandVerdict {
	v := CommandVerdict{}
	segments := splitCommandSegments(cmd)
	if len(segments) == 0 {
		return v
	}

	var prevBase string
	for _, seg := range segments {
		if len(seg) == 0 {
			continue
		}
		base := path.Base(seg[0])
		base = strings.ToLower(strings.TrimSpace(base))
		if base == "" || base == "sudo" || base == "env" || strings.Contains(seg[0], "=") {
			// 跳过前缀/赋值，继续看后面的真实程序
			if len(seg) > 1 {
				base = path.Base(seg[1])
				base = strings.ToLower(strings.TrimSpace(base))
			} else {
				continue
			}
		}
		v.Binaries = append(v.Binaries, base)

		// 1. 扫描器/爆破器白名单制（第三章 3）：默认禁用，需逐次申请。
		if denyBinaries != nil && denyBinaries[base] {
			return CommandVerdict{Deny: true, Rule: "R:scanner_not_approved",
				Reason:   "扫描器/爆破器默认禁用，需逐次向本方申请（规范第三章 3）：" + base,
				Binaries: v.Binaries, Targets: v.Targets}
		}

		// 2. `... | base64 -d | sh`：解码后再执行，静态看不见真实动作。
		if (base == "sh" || base == "bash" || base == "zsh" || base == "dash") && len(seg) == 1 {
			if decodeBinaries[prevBase] {
				return CommandVerdict{Deny: true, Rule: "R:inline_decode_exec",
					Reason: "禁止解码后执行（规范第三章 1、6.4）", Binaries: v.Binaries, Targets: v.Targets}
			}
		}

		// 3. 内联解释器：`bash -c '...'`
		if flags, ok := inlineInterpFlags[base]; ok && hasAnyFlag(seg, flags) {
			return CommandVerdict{Deny: true, Rule: "R:inline_interpreter",
				Reason:   "禁止内联解释器（bash -c / python -c 等），静态判定无法确认真实动作（规范第三章 1、6.4）",
				Binaries: v.Binaries, Targets: v.Targets}
		}

		// 4. RCE 模式：只允许只读身份命令（规范 6.4）
		if opt.RCEMode && !isRCEAllowed(base, lex) {
			return CommandVerdict{Deny: true, Rule: "R6_rce_not_allowlisted",
				Reason:   "RCE/webshell 会话只允许只读身份命令（whoami/id/uname/hostname/ifconfig/ipconfig），实际为 " + base,
				Binaries: v.Binaries, Targets: v.Targets}
		}

		// 5. 敏感文件读取（规范 5.4 即停）
		if readBinaries[base] {
			for _, w := range seg[1:] {
				lower := strings.ToLower(w)
				for _, tok := range sensitivePathTokens {
					if strings.Contains(lower, tok) {
						return CommandVerdict{Deny: true, Rule: "R5_sensitive_read",
							Reason:   "禁止读取敏感文件/凭据（规范 5.4 命中即停）：" + tok,
							Binaries: v.Binaries, Targets: v.Targets}
					}
				}
			}
		}

		// 6. 收集目标（URL / host / IP），供范围校验
		for _, w := range seg[1:] {
			v.Targets = append(v.Targets, extractTargets(w)...)
		}
		if copyOrExfil[base] {
			// 外带程序的目标同样要过范围校验（红线 8）
			for _, w := range seg[1:] {
				if strings.Contains(w, "://") {
					if u, err := url.Parse(w); err == nil && u.Hostname() != "" {
						v.Targets = append(v.Targets, u.Hostname())
					}
				}
			}
		}
		prevBase = base
	}
	v.Targets = dedupeStrings(v.Targets)
	return v
}

func isRCEAllowed(bin string, lex *Lexicon) bool {
	if lex == nil {
		switch bin {
		case "whoami", "id", "uname", "hostname", "ifconfig", "ipconfig":
			return true
		}
		return false
	}
	if lex.rceAllow[bin] {
		return true
	}
	// uname -a 归一到 uname
	return lex.rceAllow[bin]
}

func hasFlag(seg []string, flags ...string) bool {
	for _, w := range seg[1:] {
		for _, f := range flags {
			if w == f {
				return true
			}
		}
	}
	return false
}

func hasAnyFlag(seg []string, flags []string) bool { return hasFlag(seg, flags...) }

// splitCommandSegments 把命令行切成"一条命令"，处理引号、反斜杠与 ; && || | 换行。
// 不做完整 shell 解析，但足以避免 `"a; rm -rf /"` 这类引号内误切。
func splitCommandSegments(cmd string) [][]string {
	var (
		segs    [][]string
		cur     []string
		word    strings.Builder
		inWord  bool
		quote   rune
		escaped bool
	)
	flushWord := func() {
		if inWord {
			cur = append(cur, word.String())
			word.Reset()
			inWord = false
		}
	}
	flushSeg := func() {
		flushWord()
		if len(cur) > 0 {
			segs = append(segs, cur)
			cur = nil
		}
	}
	runes := []rune(cmd)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			word.WriteRune(r)
			inWord = true
			escaped = false
			continue
		}
		if quote != 0 {
			switch {
			case r == '\\' && quote == '"':
				escaped = true
			case r == quote:
				quote = 0
			default:
				word.WriteRune(r)
				inWord = true
			}
			continue
		}
		switch r {
		case '\\':
			escaped = true
			inWord = true
		case '\'', '"':
			quote = r
			inWord = true
		case ' ', '\t', '\r':
			flushWord()
		case '\n', ';':
			flushSeg()
		case '&', '|':
			if i+1 < len(runes) && runes[i+1] == r { // && / ||
				i++
				flushSeg()
			} else { // 管道 / 后台
				flushSeg()
			}
		case '(', ')', '{', '}':
			flushSeg()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	flushSeg()
	return segs
}

// extractTargets 从单个参数里抽出可能的网络目标。
func extractTargets(w string) []string {
	var out []string
	if strings.Contains(w, "://") {
		if u, err := url.Parse(w); err == nil && u.Hostname() != "" {
			out = append(out, u.Hostname())
			return out
		}
	}
	// host:port
	if host, port, err := net.SplitHostPort(w); err == nil && port != "" {
		if net.ParseIP(host) != nil || strings.Contains(host, ".") {
			out = append(out, host)
			return out
		}
	}
	if ip := net.ParseIP(w); ip != nil {
		out = append(out, ip.String())
		return out
	}
	// 裸域名（含点且无空格、非路径）
	if strings.Contains(w, ".") && !strings.HasPrefix(w, "/") && !strings.ContainsAny(w, " \t=@'\"") &&
		!strings.Contains(w, "..") && len(w) < 256 {
		if _, err := url.Parse("http://" + w); err == nil {
			out = append(out, w)
		}
	}
	return out
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
