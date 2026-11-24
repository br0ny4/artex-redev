package policy

import (
	"net"
	"path"
	"regexp"
	"strings"
)

// 宿主机边界（host boundary）。
//
// 为什么单独一层：在线测试域和离线分析域的"危险"不是同一件事。
//
//	在线域：危险是"打坏了客户业务"——由范围/语义/预算/红线管；
//	离线域：危险是"打坏了自己的机器、或把不可信代码放到宿主机上跑起来"——
//	       范围管不到（目标是本机文件），语义分级也管不到（没有 HTTP 请求）。
//
// 所以这里只做一件事：判断一条本地命令是否越过宿主机边界。这一层始终启用（在线域
// 也拦，因为操作者的机器一样会被 rm -rf / 打坏），且判定不依赖任何授权上下文。
//
// 与规范执行层的分工：
//   - 这里 = 硬边界（宿主机/本地环境的完整性），命中即拒这条命令；
//   - 规范执行层（范围/语义/预算）= 作业边界，命中可能是 deny，也可能升级为全量停止。
//
// 离线域的宽松化（容许内联解释器、回环目标、样本内字符串命中等）由 CommandOptions
// 显式传入，见 AnalyzeCommand。

// 宿主机边界命中的规则名。
const (
	RuleHostDestructive = "H:host_destructive" // 破坏宿主机/本地环境
	RuleHostExecScoped  = "H:host_exec_scoped" // 直接执行授权目录内的文件（样本/被审计代码）
)

// dangerousSystemRoots 是删除/改权限类命令不允许指向的系统根。
// 只做精确匹配（见 isDangerousSystemRoot），避免把 /tmp、/var/tmp 下的正常清理也拦掉。
var dangerousSystemRoots = []string{
	"/", "/*", "~", "$HOME", "${HOME}",
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt", "/proc", "/root",
	"/sbin", "/sys", "/System", "/Library", "/usr", "/var",
	"c:", "c:/", "c:/windows", "c:/program files", "c:/users",
}

// deviceWriteAllowlist 是 dd of= 允许的目标（写黑洞/字符设备不破坏磁盘）。
var deviceWriteAllowlist = map[string]bool{
	"/dev/null": true, "/dev/zero": true, "/dev/full": true,
	"/dev/stdout": true, "/dev/stderr": true, "/dev/stdin": true,
	"/dev/random": true, "/dev/urandom": true, "/dev/tty": true,
}

// hostDangerPayloadPatterns 用于扫"藏在参数里的动作"——内联解释器（python -c …）、
// 以及引号内的 shell 载荷。分段解析看不到这些，只能按特征扫。
var hostDangerPayloadPatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\brm\s+[^;|&\n]*?(?:--no-preserve-root\s+)?(?:-{1,2}[a-z-]+\s+)*/(?:[\s'"')\*]|$)`),
		"删除文件系统根目录（rm -rf /）会直接摧毁宿主机"},
	{regexp.MustCompile(`(?i)\brm\s+[^;|&\n]*?\s(?:/etc|/boot|/usr|/var|/dev|/bin|/sbin|/lib|/lib64|/sys|/proc)(?:/\S*)?(?:\s|$)`),
		"删除系统目录会直接摧毁宿主机"},
	{regexp.MustCompile(`(?i)\bdd\b[^;|&\n]*of=/dev/(?:sd|nvme|hd|disk|mmcblk|vd|xvd|rdisk)`),
		"向块设备写入原始数据会擦掉磁盘"},
	{regexp.MustCompile(`(?i)\bmkfs(?:\.[a-z0-9]+)?\s`),
		"格式化文件系统会擦掉磁盘"},
	{regexp.MustCompile(`(?i)(?:^|[;&|\s])(?:shutdown|reboot|poweroff|halt)\s`),
		"关机/重启会中断宿主机上所有工作"},
	{regexp.MustCompile(`(?i)\bchmod\s+(?:-R\s+|--recursive\s+)[0-7]{3,4}\s+/(?:\s|\*|$)`),
		"递归改根目录权限会让系统不可用"},
	{regexp.MustCompile(`(?i)\bchown\s+(?:-R\s+|--recursive\s+)\S+\s+/(?:\s|\*|$)`),
		"递归改根目录属主会让系统不可用"},
	{regexp.MustCompile(`:\(\)\s*\{[^}]*:\|\:[^}]*\}\s*;\s*:`),
		"fork bomb 会耗尽宿主机进程资源"},
	{regexp.MustCompile(`(?i)(?:/etc/shadow|/etc/sudoers|id_rsa|id_ed25519)`),
		"读取宿主机凭据是越界行为（只允许读与本次分析有关的数据）"},
}

// isLoopbackTarget 判断命令里的目标是不是本机回环。
// 离线/本地域把它视为"本地环境"，不做横向访问的外网地址判定。
func isLoopbackTarget(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.Trim(h, "[]")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// scanHostDangerPayload 扫描一段"看不见动作"的载荷（内联解释器参数、引号内容）。
func scanHostDangerPayload(payload string) (reason string, hit bool) {
	for _, p := range hostDangerPayloadPatterns {
		if p.re.MatchString(payload) {
			return p.reason, true
		}
	}
	return "", false
}

// isDangerousSystemRoot 判断"删除/改权限的目标"是不是系统根。
// "/" 与 "<root>/*" 都算；"/etc/nginx" 这种子目录不算（把它删坏与删 /etc 同性质，
// 但误报代价高——宿主机被摧毁的典型行为是整根或整目录）。
func isDangerousSystemRoot(target string) bool {
	t := strings.TrimSpace(target)
	if t == "" {
		return false
	}
	t = strings.ReplaceAll(t, "\\", "/")
	t = strings.ToLower(t)
	if t == "/*" || t == "/**" || t == "/ *" {
		return true
	}
	t = path.Clean(t)
	for _, r := range dangerousSystemRoots {
		if t == r || t == r+"/" {
			return true
		}
	}
	return false
}

// isDeviceWrite 判断 dd 的目标是否是块设备（写黑洞类设备放行）。
func isDeviceWrite(arg string) bool {
	i := strings.Index(strings.ToLower(arg), "of=")
	if i < 0 {
		return false
	}
	dev := strings.TrimSpace(arg[i+3:])
	dev = strings.Trim(dev, `"'`)
	if !strings.HasPrefix(dev, "/dev/") {
		return false
	}
	return !deviceWriteAllowlist[dev]
}

// pathUnderAny 判断 p 是否在任意一个授权根之内（含根本身）。
// 只做词法判断，不做符号链接解析：这里用于"是否需要看一眼磁盘"，真正的存在性核对
// 在服务端（可达性核对），判定层保持无 IO。
func pathUnderAny(p string, roots []string) bool {
	if p == "" {
		return false
	}
	c := path.Clean(strings.ReplaceAll(p, "\\", "/"))
	for _, r := range roots {
		r = path.Clean(strings.ReplaceAll(strings.TrimSpace(r), "\\", "/"))
		if r == "" || r == "." {
			continue
		}
		if c == r || strings.HasPrefix(c, r+"/") {
			return true
		}
	}
	return false
}

// looksLikePath 判断一个参数是不是"路径形态"，还是只是普通词/模式。
// 用于敏感路径判定：`grep -i shadow sample.bin` 里的 shadow 是搜索词，不是文件；
// 而 `cat ~/.ssh/id_rsa`、`strings /etc/shadow` 才是真的在碰敏感文件。
func looksLikePath(w string) bool {
	w = strings.TrimSpace(w)
	if w == "" {
		return false
	}
	switch {
	case strings.HasPrefix(w, "/"), strings.HasPrefix(w, "~/"), strings.HasPrefix(w, "./"),
		strings.HasPrefix(w, "../"), strings.HasPrefix(w, "..\\"), strings.HasPrefix(w, "\\\\"):
		return true
	case len(w) > 2 && w[1] == ':' && (w[2] == '/' || w[2] == '\\'):
		return true // Windows 盘符
	}
	return false
}

// scopedExecTarget 判断这条命令是否在"直接执行授权目录里的文件"。
// 覆盖三种形态：
//  1. 直接执行绝对路径：/srv/triage/samples/inbox/a.bin
//  2. 先 cd 再执行相对路径：cd /srv/triage/samples/inbox && ./a.bin
//  3. 用解释器执行：bash /srv/audit/repo/build.sh、python3 /srv/audit/repo/poc.py
//
// 授权目录（scope.local_paths）是"允许读的清单"，不是"允许执行的清单"：
// 样本和被审计代码恰恰是这次要分析的不可信输入，把它们放到宿主机上跑起来，
// 就是越过宿主机边界——除非域包显式允许（allow_executing_scoped_files）。
func scopedExecTarget(base, raw string, args []string, cwd string, roots []string) string {
	if len(roots) == 0 {
		return ""
	}
	if interpBinaries[base] {
		for _, a := range args {
			if strings.HasPrefix(a, "-") || !looksLikePath(a) {
				continue
			}
			if p := resolveUnderRoots(a, cwd, roots); p != "" {
				return p
			}
		}
		return ""
	}
	if !looksLikePath(raw) {
		return ""
	}
	return resolveUnderRoots(raw, cwd, roots)
}

func resolveUnderRoots(p, cwd string, roots []string) string {
	c := strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(c, "/") {
		if cwd == "" {
			return ""
		}
		c = path.Join(cwd, c)
	}
	c = path.Clean(c)
	if pathUnderAny(c, roots) {
		return c
	}
	return ""
}

// interpBinaries 会"把参数当代码执行"的解释器。它们执行授权目录里的脚本，
// 与直接执行样本同性质。
var interpBinaries = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true, "php": true,
	"pwsh": true, "powershell": true, "osascript": true,
}

// hostDangerSegment 做分段级的宿主机边界判定（不依赖参数内容扫描）。
func hostDangerSegment(base string, seg []string) (rule, reason string, hit bool) {
	args := seg[1:]
	switch base {
	case "rm", "del", "erase", "rmdir", "unlink", "srm", "shred":
		for _, a := range args {
			if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "/") && strings.EqualFold(base, "del") {
				continue
			}
			if isDangerousSystemRoot(a) {
				return RuleHostDestructive, "删除系统根/家目录会直接摧毁宿主机：" + a, true
			}
		}
	case "dd":
		for _, a := range args {
			if isDeviceWrite(a) {
				return RuleHostDestructive, "向块设备写入原始数据会擦掉磁盘：" + a, true
			}
		}
	case "mkfs", "mke2fs", "mkswap", "wipefs":
		for _, a := range args {
			if strings.HasPrefix(a, "/dev/") {
				return RuleHostDestructive, "格式化/擦除块设备会摧毁磁盘：" + base + " " + a, true
			}
		}
	case "shutdown", "reboot", "halt", "poweroff":
		return RuleHostDestructive, "关机/重启会中断宿主机上所有工作：" + base, true
	case "chmod", "chown", "chgrp":
		recursive := false
		for _, a := range args {
			if a == "-R" || a == "--recursive" || strings.EqualFold(a, "-r") && base != "chmod" {
				recursive = true
			}
		}
		if recursive {
			for _, a := range args {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if isDangerousSystemRoot(a) {
					return RuleHostDestructive, "递归修改系统目录权限/属主会让系统不可用：" + a, true
				}
			}
		}
	}
	if strings.HasPrefix(base, "mkfs") {
		for _, a := range args {
			if strings.HasPrefix(a, "/dev/") {
				return RuleHostDestructive, "格式化块设备会摧毁磁盘：" + base + " " + a, true
			}
		}
	}
	return "", "", false
}
