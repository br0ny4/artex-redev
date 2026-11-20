// Package docscheck 把"文档里的说法"与"代码里的事实"钉在一起。
//
// 定位文档（docs/redev/10-positioning.md）声称某条能力落在某个文件、某个接口、某个测试上；
// 这些说法如果没人校验，半年后就会变成过时的故事。这里的测试负责在 CI 里把它们拽住：
// 文档里写到的代码坐标必须存在、接口必须有注册、测试锚点必须是真实函数。
package docscheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const docPath = "docs/redev/10-positioning.md"

// resolveDocRelative 先按仓库根解析，再按文档同级目录解析：
// 同目录的兄弟文档（如 `09-diff-from-upstream.md`）在文里只写文件名。
func resolveDocRelative(root, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat(filepath.Join(root, p)); err == nil {
		return filepath.Join(root, p)
	}
	return filepath.Join(root, filepath.Dir(docPath), p)
}

// 文档必须保留的章节：删章节等于删承诺，测试期的人得先改这里。
var requiredSections = []string{
	"## 1. 一句话定位",
	"## 2. 为什么选 ARTEX",
	"## 3. 守什么",
	"## 4. 改什么",
	"## 5. 风险登记",
	"## 6. 评审清单",
	"## 7. 本文档如何被校验",
}

var (
	backtickRe = regexp.MustCompile("`([^`\n]+)`")
	// 文件坐标：path/to/file.ext 或 path/to/file.ext:123
	fileRe = regexp.MustCompile(`^([A-Za-z0-9_./-]+\.(?:go|sql|md|yaml|yml|ts|tsx|sh))(?::(\d+))?$`)
	// 目录坐标：path/to/dir/
	dirRe = regexp.MustCompile(`^([A-Za-z0-9_./-]+)/$`)
	// 测试锚点：`pkg TestName`（出现在 §4 的表格里）
	anchorRe = regexp.MustCompile(`^([a-z][a-z0-9_/]*)\s+(Test[A-Za-z0-9_]+)$`)
)

// repoRoot 从当前工作目录向上找 go.mod。go test 的工作目录随 Go 版本/调用方式
// 不一定等于包目录，硬编码相对路径会在 CI 和本地行为不一致。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目录失败: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("向上找不到 go.mod：测试必须在仓库内运行")
		}
		dir = parent
	}
}

func readServerSources(t *testing.T, root string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "server", "*.go"))
	if err != nil {
		t.Fatalf("列 server/ 源码失败: %v", err)
	}
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读 %s 失败: %v", f, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestPositioningDocMatchesCode 断言定位文档的每个"可机器校验"说法都还成立。
func TestPositioningDocMatchesCode(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, docPath))
	if err != nil {
		t.Fatalf("读定位文档失败：%v（若文档被移动，请同步本测试）", err)
	}
	doc := string(data)
	var problems []string
	fail := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	for _, sec := range requiredSections {
		if !strings.Contains(doc, sec) {
			fail("缺少章节 %q：删章节等于删承诺，先改测试再删文档", sec)
		}
	}

	serverSrc := readServerSources(t, root)
	tokens := backtickRe.FindAllStringSubmatch(doc, -1)
	for _, m := range tokens {
		tok := strings.TrimSpace(m[1])
		if tok == "" || strings.Contains(tok, "...") || strings.Contains(tok, "…") {
			continue
		}
		// 接口：必须在 server/ 有注册（Go 1.22 mux 模式串）。
		if strings.HasPrefix(tok, "/api/") {
			if !strings.Contains(serverSrc, tok) {
				fail("接口 %q 在 server/ 内找不到注册：要么接口被删了，要么文档该更新", tok)
			}
			continue
		}
		// 文件坐标：必须存在；带行号时行号不能越界（行号是最容易过期的锚点）。
		if fm := fileRe.FindStringSubmatch(tok); fm != nil {
			path := resolveDocRelative(root, fm[1])
			content, err := os.ReadFile(path)
			if err != nil {
				fail("代码坐标 %q 指向的文件不存在（已按仓库根与文档同级目录分别尝试）：%v", tok, err)
				continue
			}
			if fm[2] != "" {
				line, _ := strconv.Atoi(fm[2])
				lines := strings.Count(string(content), "\n")
				if line > lines {
					fail("代码坐标 %q 行号越界（文件只有 %d 行）：文件改动后请更新行号", tok, lines)
				}
			}
			continue
		}
		// 目录坐标。
		if dm := dirRe.FindStringSubmatch(tok); dm != nil && !strings.HasPrefix(tok, "/") {
			if st, err := os.Stat(filepath.Join(root, dm[1])); err != nil || !st.IsDir() {
				fail("目录坐标 %q 不存在", tok)
			}
		}
	}

	// §4 表格里的测试锚点：必须是真实测试函数，防止"文档说被这条测试守着"其实没有。
	for _, m := range tokens {
		tok := strings.TrimSpace(m[1])
		am := anchorRe.FindStringSubmatch(tok)
		if am == nil {
			continue
		}
		pkg, testName := am[1], am[2]
		pkgDir := filepath.Join(root, pkg)
		files, err := filepath.Glob(filepath.Join(pkgDir, "*_test.go"))
		if err != nil || len(files) == 0 {
			fail("测试锚点 %q：包目录 %s 下没有 *_test.go", tok, pkg)
			continue
		}
		found := false
		for _, f := range files {
			src, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if strings.Contains(string(src), "func "+testName+"(") {
				found = true
				break
			}
		}
		if !found {
			fail("测试锚点 %q 找不到：%s 包里没有 func %s；要么补测试，要么从文档里删掉这条承诺", tok, pkg, testName)
		}
	}

	if len(problems) > 0 {
		t.Fatalf("定位文档与代码不一致（%d 处）：\n- %s\n\n修复方式：同步更新代码/测试/文档三者，或调整 docs/redev/10-positioning.md 对应的坐标。",
			len(problems), strings.Join(problems, "\n- "))
	}
}
