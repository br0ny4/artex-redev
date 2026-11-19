# 02 — Tooling Survey: 0day-mining / RE / audit capability for an ARTEX fork

**Date:** 2026-11-18 · **Status:** research complete, decisions proposed
**Scope:** external tools we would integrate into ARTEX primarily over MCP, so planner/worker agents can call them.
**Sibling docs:** [00-arch-map.md](./00-arch-map.md), [01-abuse-and-status.md](./01-abuse-and-status.md)

## How this was verified

Every row was checked against a primary source on **2026-11-18**: GitHub REST API (`license`, `stargazers_count`,
`pushed_at`), the repo README as served by `raw.githubusercontent.com`, npm/PyPI registry metadata, and official docs
pages. Star counts and dates are a **snapshot**, not a trend.

| Marker | Meaning |
| --- | --- |
| ✅ | Confirmed from primary source; date or version quoted |
| ⚠️ | Confirmed but with an important caveat / partial evidence |
| ❌ | Could **not** verify — do not plan on it without checking first |

---

## 0. TL;DR — what changed in 2025–2026 that invalidates older tutorials

1. **The classic `ida-pro-mcp` GUI-server + `localhost:13337/mcp` setup is now legacy.** mrexodia's repo has moved to an
   **idalib-based, stdio-first headless server** (`idalib-mcp`), the old GUI plugin is marked *"no longer recommended and will
   eventually be deprecated"*, and the README itself now says **"I recommend using the Official Hex-Rays IDA MCP Server
   instead"** ([README](https://github.com/mrexodia/ida-pro-mcp), [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp)).
2. **Ghidra's ecosystem consolidated on Ghidra 12.1.4 (and 12.2 needs Java 25).** Plugins built for 11.x do not load.
3. **Binary Ninja 6.0 "Krypton" (2026-09-03) ships a native MCP server** (HTTP, default port `24642`), which is why
   `symgraph/BinAssistMCP` is now marked *planned archival* ([BN MCP docs](https://docs.binary.ninja/guide/mcp.html)).
4. **VirusTotal now ships an official MCP server, and it is a hosted remote MCP** (`https://ai.virustotal.com/mcp`, OAuth,
   free VTAI tier) — no API key, no local process ([repo](https://github.com/VirusTotal/virustotal-mcp)).
5. **Semgrep's MCP surface split:** the standalone `semgrep/mcp` repo is **archived** (2025-10-28) and folded into the
   `semgrep` CLI as `semgrep mcp`; the documented product is now a **hosted** MCP for the paid AppSec Platform
   (Teams/Enterprise) ([docs](https://docs.semgrep.dev/mcp/overview)).
6. **`aliasrobotics/cai` (Cyber Security AI) is archived** (2026-08-22). Do not build the fork on it.
7. **Cuckoo Sandbox is dead** (archived, last push 2022-05-03). CAPE v2 is the live lineage.

---

## 1. Item 1 — IDA Pro MCP and Ghidra / Binary Ninja counterparts

> Context: IDA Pro is commercial. The MCP server is a Python process that talks to IDA (in-process plugin, or `idalib`
> headless). IDA Free is **not** supported by mrexodia's server.

| Tool | URL | License | Transport / Interface | Key capabilities | Maintenance | Integration notes |
| --- | --- | --- | --- | --- | --- | --- |
| **ida-pro-mcp** (mrexodia) ✅ | https://github.com/mrexodia/ida-pro-mcp · PyPI `ida-pro-mcp` 1.4.0 | **MIT** | **stdio** (`uv run idalib-mcp --stdio`) or **Streamable/SSE HTTP** (`uv run idalib-mcp --host 127.0.0.1 --port 8745`; GUI mode `--transport http://127.0.0.1:8744/sse`). Legacy `:13337/mcp?ext=dbg` survives only as the debugger-extension endpoint | ~60 tools: `decompile`, `disasm`, `xrefs_to`, `xrefs_to_field`, `callees`, `callgraph`, `basic_blocks`, `list_funcs`, `imports`, `list_globals`, `lookup_funcs`, `int_convert`, `get_bytes`/`get_int`/`get_string`, `set_comments`, `rename`, `patch_asm`, `patch`, `put_int`, `set_type`, `infer_types`, `declare_type`, `define_func`/`define_code`/`undefine`, `stack_frame`, `read_struct`, `search_structs`, `find_bytes`/`find_insns`/`find_regex`/`find`, `export_funcs`, `py_eval` (arbitrary Python in IDA), `analyze_funcs`; hidden `dbg_*` debugger set (start/continue/step/bp/regs/read/write/stacktrace); resources `ida://idb/*`, `ida://structs`, `ida://xrefs/from/{addr}` | ✅ active — pushed **2026-11-12**, 13.5k★, release 1.5.0. ⚠️ README now *recommends the official server instead*; GUI plugin path is deprecated | Requires **IDA 8.3+ (9 recommended)**, Python **3.11+**, `idapyswitch`; headless needs `idalib` activated globally (`py-activate-idalib.py`). Install: `pip install ida-pro-mcp` + `ida-pro-mcp --install` **or** the newer `uv run idalib-mcp`. Per-session model: every call carries a `database=` session id from `idb_open`; `--max-workers` (default 4). **Commercial IDA licence required** |
| **ida-mcp** (Hex-Rays official) ✅ | https://github.com/HexRaysSA/ida-mcp (announcement: https://hex-rays.com/blog/hex-rays-ida-mcp-server) | **MIT** | stdio + headless workers; GUI plugin optional (`ida-mcp` plugin), `gui=true` to open a file into the IDA GUI | Same class of operations (decompile / xrefs / rename / patch / list), headless-first with `idb_*` lifecycle | ✅ new — created 2026-08-27, pushed 2026-10-28, 1.6k★ | Requires **IDA 9.4+ with idalib**, Python 3.11+, `git` + `uv` on PATH. Install: `uvx ida-hcli mcp install` (or `hcli mcp install`). Explicitly recommends **disabling other IDA MCP servers** to avoid agent confusion. **Vendor-controlled** — best forward bet, but new |
| **GhidraMCP** (LaurieWired) ✅ | https://github.com/LaurieWired/GhidraMCP | **Apache-2.0** | Ghost: MCP client is **stdio** (`uvx --from git+… ghidra-mcp --ghidra-server http://127.0.0.1:8080/`) or **streamable-http** (`--transport streamable-http --mcp-port 8081` → `http://127.0.0.1:8081/mcp`). Underneath, a Ghidra plugin exposes an HTTP bridge on **:8080** | `decompile_function`, `list_methods`/`classes`/`imports`/`exports`, `search_functions_by_name`, `rename_function`/`rename_data`, `set_function_signature`, `set_comment`/`remove_comment`, `get_disassembly`, `read_memory`, `list_strings`, `create_data`/`set_data_type`, xref/struct/segment helpers | ✅ pushed **2026-10-10**, 12.0k★ | Requires **Ghidra 12.1.4 exactly** (extension zip built per version), `uv`. Free, no seat cost. Two-process (Ghidra GUI + MCP bridge) → awkward in a container; **use only for analyst-desktop workflows**, not server-side batch |
| **ghidra-mcp** (bethington) ✅ | https://github.com/bethington/ghidra-mcp | **Apache-2.0** | Ghidra GUI extension + Python MCP bridge (`ghidra_mcp_bridge-*.whl`), **and a headless server**, incl. **Docker deployment** | **209 tools** — decompile/patch/xrefs/renames plus P-code emulation, live debugger integration, P-code graph data-flow analysis, `analyze_function_completeness` scoring, convention enforcement, batch ops, Ghidra Server integration, lazy tool loading | ✅ very active — pushed **2026-11-18**, 6.3k★ | **Best headless Ghidra option.** Ghidra 12.1.4 + Java 21 + `uv`. 209 tools is a context-cost problem → needs tool filtering / per-agent scoping in ARTEX |
| **ReVa** (cyberkaida, *Reverse Engineering Assistant*) ✅ | https://github.com/cyberkaida/reverse-engineering-assistant | **Apache-2.0** | Ghidra **extension** hosting an MCP server | Deliberately **many small tools** with schema tolerance + "redirect correctable mistakes back to the LLM"; designed for long-form RE, large binaries and **firmware images**; reports namespace + xrefs alongside decompilation to force exploration; supports program diffing | ✅ pushed **2026-11-17**, 968★ | Ghidra **12.0+** (12.2+ needs Java 25). Its "small tools + context-rot control" design is the most interesting *prompt-architecture* prior art for us — see §7 |
| **GhidrAssistMCP** (symgraph) ✅ | https://github.com/symgraph/GhidrAssistMCP | **MIT** | Native Ghidra **extension** MCP server | Ghidra-native MCP endpoint without the Python bridge hop | ✅ pushed 2026-11-15, 813★ | Lower-latency alternative to the two-process GhidraMCP design |
| **BinAssistMCP** (symgraph) ✅ | https://github.com/symgraph/BinAssistMCP | **MIT** | **SSE** + **Streamable HTTP** (FastMCP) | **45 tools** (open/get_code(`decompile`/`hlil`/`mlil`/`llil`/`disasm`/`pseudo_c`)/xrefs/comments/export_program), 8 MCP resources (`binassist://…`), 7 prompts, MCP 2025-11-25 annotations | ⚠️ **planned archival** (README), last push 2026-10-09, 50★ | Superseded by **Binary Ninja 6 native MCP**. Only relevant if we standardise on BN 5.x |
| **Binary Ninja 6 native MCP** (Vector35) ✅ | https://docs.binary.ninja/guide/mcp.html · API repo https://github.com/Vector35/binaryninja-api (MIT) | **Commercial** (BN licence, Personal ~$299+); the SDK/API repo is MIT | **HTTP only**, hosted inside the GUI: enable `ui.mcp.enabled`, `ui.mcp.port` (default **24642**), `ui.mcp.endpoint`, optional `ui.mcp.token`; start with *Plugins → MCP → Start Server* | Native inspection/edit tools (~32 count reported by a third-party probe), HLIL/MLIL text, active-view selection | ✅ shipped in **BN 6.0 "Krypton" 2026-09-03** | ⚠️ **GUI-hosted HTTP only**; no standalone `binaryninja_mcp` on Windows yet. Hard to run server-side/headless. Paid seat |

**Item 1 verdict.** The question *"does it need IDA 8.x/9.x?"* → **8.3+ for mrexodia's, 9.4+ for the official Hex-Rays one**;
the port question → **`13337` is legacy**, current defaults are **`8744` (GUI SSE) / `8745` (idalib HTTP)** and stdio is preferred.
For a server-side ARTEX agent the only sane shape is **`idalib-mcp --stdio` (or `--port`) in the worker container**, not the GUI plugin.

---

## 2. Item 2 — "rea" is genuinely ambiguous; here is what actually exists

The term was not resolvable to one thing. All four candidate readings are real-ish, but **three of them are not what a
security RE workflow means**. Stated explicitly rather than guessed:

| Reading | Exists? | URL | What it is | Verdict |
| --- | --- | --- | --- | --- |
| **(a) RevEng.AI** — commercial binary-analysis API, "X-Ray for compiled software" | ✅ **Yes**, commercial SaaS | https://reveng.ai/ · SDKs: https://github.com/RevEngAI/sdk-typescript (also Python SDK) | Upload binary → AI models recover structure/symbols on **stripped binaries**; 183 s median end-to-end; **REST API + Python SDK + STIX/TAXII**; native plugins for **IDA Pro, Ghidra, Binary Ninja**; on-prem/air-gapped/VPC ("your samples never leave your boundary"); claims 1.4 B+ binaries in corpus | **Most plausible referent.** ⚠️ Closed + paid; cloud upload means **sample exfiltration** unless on-prem. No MCP server found ❌ — would need a thin REST wrapper |
| **(b) a literal tool named `rea`** | ✅ but irrelevant | PyPI [`rea`](https://pypi.org/project/rea/) 0.1.1 = *"REceiver Array Analysis software"* (radio astronomy); npm [`rea`](https://registry.npmjs.org/rea) 0.0.1 = *"fancy wrapper over connect.router"* (2012-era Node) | Nothing security-related | ❌ **Not a security tool.** Both packages are abandoned and unrelated |
| **(c) radare2 / r2 MCP** | ✅ **Yes**, official | https://github.com/radareorg/radare2-mcp | C rewrite on native r2 APIs; **stdio by default**, **HTTP MCP** with `-H [addr:]port`, per-session `-X max:idle` via `X-Session-ID`, `-H 0.0.0.0:PORT` needs `-a <token>`/`-A`; `r2pm -Uci r2mcp`; also an r2 **core plugin** mode and a **Docker** image; read-only (`-R`), sandbox lock, tool allow/deny (`r2mcp.enabled/disabled`), `yolo`/`approve` gates | **Strong MVP candidate** — see §4. 366★, MIT, pushed 2026-11-17, targets radare2 **6.2.4**. Tools include `open_file`, `analyze`, `sql` (via r2xsql, writes excluded from `-R`), `settings`, `random`, plus the full r2 command surface behind `-r` |
| **(d) "REA" = Reverse Engineering Assistant** | ✅ **Yes** | https://github.com/cyberkaida/reverse-engineering-assistant (**ReVa**) · also generic "RE assistant" projects, e.g. https://github.com/Zfinix/eleven (agent-first RE, ACP), https://github.com/haikow/claude-reverse-skills, https://github.com/EncidXVII/claude-reverse-engineering-skill | ReVa = Ghidra MCP server for AI-assisted RE (see §1) | **Second most plausible referent if the user meant "the RE assistant MCP"** — that is ReVa, and it only works inside Ghidra |

**Recommendation:** treat "rea" as **(a) RevEng.AI** if the ask was a *capability/API*, and as **(c) r2mcp** if the ask was a
*tool to install*. Ask the team to confirm before spending money on (a).

---

## 3. Item 3 — CDP / browser-side tooling

> Why this matters for a 0day fork: most 2026 "0day" value in web targets is **client-side** — auth/business-logic bypass,
> prototype pollution, hidden/undocumented APIs, Web3 dApp transaction flows. That needs a *live CDP session*, not an HTTP client.

| Tool | URL | License | Transport / Interface | Key capabilities | Maintenance | Integration notes |
| --- | --- | --- | --- | --- | --- | --- |
| **chrome-devtools-mcp** ✅ | https://github.com/ChromeDevTools/chrome-devtools-mcp · npm `chrome-devtools-mcp` **1.13.0** (2026-11-11) | **Apache-2.0** | **stdio** MCP (also a **CLI**) | **63 tools / 10 groups**: input automation (10), navigation (6), emulation (2), **performance** (`performance_start_trace`/`stop_trace`/`analyze_insight`), **network** (`list_network_requests`, `get_network_request`), debugging (`evaluate_script`, `get_console_message`, `list_console_messages`, `get_css_styles`, `lighthouse_audit`, `set_logpoints`, `screencast_*`, `take_snapshot`, `take_screenshot`), **network mocks** (`mock_network`, `remove_network_mock`), **memory/heap snapshots** (14 tools: dominators, retainers, retaining paths, duplicate strings), extensions | ✅ pushed **2026-11-18**, 58.1k★ | Best-in-class for **deep debugging** (source-mapped console stacks, traces, heap). ⚠️ **Two data-egress gotchas:** usage statistics **on by default** (`--no-usage-statistics`, or `CI`/`CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS` to disable) and performance tools may send trace URLs to **Google CrUX** (`--no-performance-crux`). Only **Chrome / Chrome-for-Testing** supported. Needs a real Chrome binary → container bloat |
| **playwright-mcp** ✅ | https://github.com/microsoft/playwright-mcp · npm `@playwright/mcp` **0.0.85** (2026-11-09) | **Apache-2.0** | **stdio** default; `--port 8931` switches to **SSE/HTTP** → client uses `url: http://localhost:8931/mcp`; Docker supported (**headless chromium only**) | ~45 `browser_*` tools: `browser_navigate`, `browser_snapshot` (a11y tree), `browser_evaluate`, `browser_run_code_unsafe`, `browser_click`/`type`/`fill_form`/`drag`/`drop`/`press_key`, `browser_console_messages`, **`browser_network_requests` + `browser_network_request`**, **`browser_route`/`route_list`/`unroute`** (request interception/mocking), **cookies** (get/list/set/delete/clear), **localStorage** and **sessionStorage** full CRUD, `browser_handle_dialog`, `browser_file_upload`, `browser_tabs`, `browser_emulate_media`, `browser_network_state_set`, `browser_find`, `browser_wait_for` | ✅ pushed **2026-11-17**, 39.8k★ | **Best fit for ARTEX web work.** Storage/cookie CRUD is exactly what auth-logic and token-forgery research needs; `browser_route` gives hidden-API discovery + response tampering. ⚠️ README explicitly says it is **not a security boundary**; `browser_run_code_unsafe` = arbitrary JS in page context → must sit behind ARTEX's `guard/intercept` approval. Also note Microsoft now pushes **`playwright-cli` + skills** as more token-efficient than MCP for coding agents |
| **puppeteer MCP** ⚠️ | Community, e.g. `merajmehrabi/puppeteer-mcp-server` ❌ *(not re-verified this pass)* | ⚠️ varies | stdio | Basic navigate/click/screenshot/eval | ❌ stale vs Playwright/CDP | **Skip.** Strictly dominated by the two above |
| **browser-use** ✅ | https://github.com/browser-use/browser-use | **MIT** | **Python library** + CLI + Browser Use Cloud (hosted agent API); *not primarily an MCP server* | Vision/DOM hybrid agents, stealth browsers (cloud), long-horizon web tasks | ✅ pushed **2026-11-18**, 121.4k★ | Use as **library inside a worker**, or consume their cloud API. Not an MCP integration. Stealth/cloud = third-party egress → bad default for client engagements |
| **CDP-based JS deobfuscation / beautify** ⚠️ | No single canonical MCP. Practical approach: CDP `Debugger.getScriptSource` + `Debugger.setBreakpointByUrl`/`setLogpoint` (`set_logpoints` in chrome-devtools-mcp) fed into a beautifier/deobfuscator | MIT-ish per tool | MCP via the two servers above, or raw CDP over WebSocket | Fetch post-transform source, pretty-print, add logpoints to dump live values, hook `JSON.parse`/`Proxy`/`fetch` to defeat packers | n/a (composed) | **Design as an ARTEX skill/skill-prompt + CDP, not a new MCP server.** `chrome-devtools-mcp`'s `set_logpoints` + `evaluate_script` already cover most of it; WebSocket frame capture comes from `get_network_request`/`list_network_requests` and CDP `Network.webSocketFrameReceived` (⚠️ no dedicated frame-dump tool exposed by either server — would need a custom CDP shim) |

**Client-side vuln suitability, ranked:** prototype pollution / DOM-XSS / hidden API enumeration → **playwright-mcp**
(`browser_evaluate`, `browser_route`) or **chrome-devtools-mcp**; auth-logic & session forgery → **playwright-mcp**
(cookie/localStorage CRUD) ; Web3 dApps → **playwright-mcp** with `browser_evaluate` to reach `window.ethereum` and
`browser_route` to tamper RPC JSON; deep perf/memory-driven bug hunting → **chrome-devtools-mcp**.

---

## 4. Item 4 — Binary / source audit tooling

| Tool | URL | License | Transport / Interface | Key capabilities | Maintenance | Integration notes |
| --- | --- | --- | --- | --- | --- | --- |
| **Semgrep** ✅⚠️ | https://github.com/semgrep/semgrep · docs https://docs.semgrep.dev/mcp/overview | **LGPL-2.1** (CE) | **`semgrep mcp`** subcommand in the CLI (added **Oct 2025**), plus a **hosted** MCP for the AppSec Platform | Pattern-based SAST, custom rules, AST dump, autofix | ✅ pushed 2026-11-18, 17.8k★. ⚠️ standalone https://github.com/semgrep/mcp repo is **archived (2025-10-28)** and merged into the CLI | ⚠️ **Licensing trap:** the *documented* MCP is the **hosted AppSec Platform** one and requires a **Teams or Enterprise plan**. Local scanning is via **Semgrep Guardian** (`semgrep mcp`). CE CLI is free & scriptable → for us, **wrap `semgrep --json` in a shell tool** rather than depend on the hosted MCP. PyPI `semgrep-mcp` 0.5.0 is the older standalone |
| **CodeQL** ✅⚠️ | https://github.com/github/codeql · CLI: https://github.com/github/codeql-cli-binaries | **MIT** (queries/libraries) · **CLI is proprietary** | CLI (`codeql database create/analyze`, SARIF) ; MCP via **`ql-mcp`** = https://github.com/advanced-security/codeql-development-mcp-server | Full dataflow/taint analysis, huge CVE query corpus, SARIF out | ✅ both pushed 2026-11-18 / 2026-11-13. `ql-mcp` 39★ | ⚠️ **Licence gotcha:** CodeQL CLI is **free only for open-source**; closed-source/commercial use needs **GitHub Advanced Security**. `ql-mcp` is oriented at *query authoring* (AST/CFG/LSP), requires **Node 25.6+** and the CodeQL CLI; its licence is **NOASSERTION** → legal review. Scriptable headless: yes, via CLI |
| **Joern** ✅ | https://github.com/joernio/joern | **Apache-2.0** | **CLI + CPG server** (`joern`, `joern-parse`, `joern-scan`, `cpgqls`); **no official MCP** | Code Property Graph for C/C++/Java/JS/Python/Kotlin/binaries; CPGQL queries for dataflow | ✅ pushed 2026-11-18, 3.7k★ | Third-party MCP bridges exist: https://github.com/epi13/joern-agent-bridge (bounded tools, Joern 4.0.583, JDK 21 baseline) and a containerised "codebadger" ⚠️. **High value** — CPG is what lets an LLM ask "does tainted input reach a sink" without reading 10k lines |
| **tree-sitter** ✅ | https://github.com/tree-sitter/tree-sitter | **MIT** | **Library** (Rust/C/Python/Node bindings); no MCP | Incremental parsing, syntax trees for ~200 langs | ✅ pushed 2026-11-18, 27.5k★ | **Building block, not a tool.** Use inside our own "code-slicer" tool to hand agents compact ASTs instead of whole files |
| **angr** ✅ | https://github.com/angr/angr | **BSD-2-Clause** | **Python API** (+ `angr-management` GUI); no MCP | Symbolic execution, CFG recovery, VEX IR, ROP, patching | ✅ pushed 2026-11-17, 9.4k★ | Fully scriptable headless; **free for commercial use**. Best "prove exploitability" engine for the price |
| **Triton** ✅ | https://github.com/JonathanSalwan/Triton | **Apache-2.0** | C++/Python library; no MCP | Dynamic symbolic execution, taint, AST lifting, x86/ARM | ✅ pushed 2026-11-11, 4.4k★ | Headless, scriptable, commercial-friendly |
| **Miasm** ✅ | https://github.com/cea-sec/miasm | **GPL-2.0** | Python library/framework; no MCP | RE framework: lifting, symbolic exec, IR, sandbox | ✅ pushed 2026-11-03, 4.0k★ | ⚠️ **GPL-2.0 copyleft** — process-isolate it (separate binary/service) to avoid contaminating ARTEX's licence posture |
| **capa** ✅ | https://github.com/mandiant/capa | **Apache-2.0** | **CLI + JSON/SARIF**; **no official MCP** | Capability detection → MITRE ATT&CK + MBC mapping; PE/ELF/.NET/shellcode/**sandbox reports** | ✅ pushed 2026-11-10, 6.3k★ | Third-party MCPs: `capa-mcp` in https://github.com/FuzzingLabs/mcp-security-hub, https://github.com/Heretek-RE/re-capa, and `rizin-mcp` ⚠️ (unofficial). Trivially wrappable CLI — **just do it ourselves** |
| **YARA** ✅ | https://github.com/VirusTotal/yara | **BSD-3-Clause** | CLI + C/Python lib (`yara-python`); no MCP | Pattern/rule matching over files & memory | ✅ pushed 2026-10-27, 10.0k★ | Fully headless & embeddable; the natural "first triage" tool |
| **FLOSS** ✅ | https://github.com/mandiant/flare-floss | **Apache-2.0** | CLI (+ JSON); no MCP | Extract obfuscated/stack/decoded strings | ✅ pushed 2026-11-15, 4.2k★ | CLI wrapper; pairs with capa. Needs Vivisect/emulation → slower, cap timeouts |
| **Detect It Easy** ✅ | https://github.com/horsicq/Detect-It-Easy | **MIT** | GUI + **CLI (`diec`)** | File/signature/packer/compiler detection, entropy | ✅ pushed 2026-11-17, 12.0k★ | `diec -j` → JSON. Cheap first-hop triage |
| **Ghidra headless** ✅ | https://github.com/NationalSecurityAgency/ghidra | **Apache-2.0** | **CLI `analyzeHeadless`** + scripts (Java/Jython); MCP via bethington/ghidra-mcp or GhidraMCP | Bulk import/analyze/decompile/export; **fully server-side** | ✅ pushed 2026-11-17, 100.5k★ | **The free, containerisable workhorse.** Java 21; heavy JVM + project dir. Pair `analyzeHeadless` (batch) with a headless MCP (interactive) |
| **Binary Ninja** ✅ | https://binary.ninja · https://docs.binary.ninja/guide/mcp.html | **Commercial** (API repo MIT) | Python/C++ API, headless (`binaryninja.headless`), native **MCP over HTTP** | HLIL/MLIL/LLIL, dataflow, patching, native MCP | ✅ BN 6.0 2026-09-03 | Paid; GUI-hosted MCP is a poor fit for containers; headless API is fine if we buy seats |
| **cwe_checker** ✅ | https://github.com/fkie-cad/cwe_checker | **LGPL-3.0** | **CLI + Docker**, Ghidra-based; no MCP | Detects CWE patterns in **binaries** | ⚠️ slow-moving — pushed 2026-09-28, 1.4k★ | ⚠️ LGPL + Ghidra dependency; run as an isolated container. Nice "binary SAST" niche, but FP rate is high ⚠️ |
| **syzkaller** ✅ | https://github.com/google/syzkaller | **Apache-2.0** | Go CLI + manager, needs **VMs/QEMU/GCE** | Coverage-guided **kernel** fuzzing | ✅ pushed 2026-11-17, 6.4k★ | Just "relevant": not wrappable as an MCP tool in a container meaningfully. **Out of scope** |
| **FuzzingBook** ⚠️ | https://www.fuzzingbook.org/ | CC-BY-NC-ND-ish (book) / code MIT ⚠️ | **Teaching material** | Fuzzing concepts/code | ✅ maintained | **Not a tool to integrate.** Reference only |

---

## 5. Item 5 — Malware-analysis specific

| Tool | URL | License | Transport / Interface | Key capabilities | Maintenance | Integration notes |
| --- | --- | --- | --- | --- | --- | --- |
| **VirusTotal MCP** (official) ✅ | https://github.com/VirusTotal/virustotal-mcp · hosted `https://ai.virustotal.com/mcp` | **Apache-2.0** | **Remote HTTP MCP with OAuth** (and a local Python stdio variant) | Tools: `get_file_report(hash)`, `get_url_report(url)`, `get_domain_report(domain)`, `get_ip_report(ip)`, `submit_file(sha256, content_base64)` (≤24 MB decoded), `submit_attachment(file)`; plus VTAI receipt/recovery | ✅ created 2026-09-08, pushed 2026-11-15, 43★ | ⚠️ **Best effort/benefit ratio in this table.** Maps directly onto ARTEX's `http` transport with OAuth headers. **Does not need our own VT API key**; uses free VTAI with current limits. ⚠️ Uploading samples = third-party disclosure; hash-only lookups are free of that concern |
| **VirusTotal API v3** ✅ | https://docs.virustotal.com/reference | Commercial ToS | REST | Full file/URL/domain/IP intel, analyses, comments, relationships | ✅ active | ⚠️ **Licensing gotcha:** the free public API key is rate-limited (≈4 req/min, 500/day) and **VT's terms restrict commercial use**; commercial use needs an enterprise agreement. Scriptable headless: yes |
| **CAPE v2** ✅ | https://github.com/kevoreilly/CAPEv2 · docs https://capev2.readthedocs.io | ⚠️ **NOASSERTION** on GitHub API (CAPE is GPL-family; verify before shipping) | **REST API (`apiv2`)** + web UI + `cape-*` CLIs; no MCP | Dynamic Windows malware analysis, **automated unpacking**, config extraction, YARA on unpacked payloads, debugger programmable via YARA, PCAP, memory dumps, instruction traces | ✅ pushed **2026-11-18**, 3.7k★ | Free demo instance: https://capesandbox.com. ⚠️ Needs a **Windows analysis VM + KVM/libvirt** → cannot live in the ARTEX container; must be a remote `http` MCP/REST wrapper. Highest capability-per-dollar in the category |
| **Cuckoo Sandbox** ✅ | https://github.com/cuckoosandbox/cuckoo | ⚠️ NOASSERTION | REST (dead) | — | ❌ **ARCHIVED, last push 2022-05-03** | **Dead. Do not integrate.** CAPE v2 is its successor |
| **Hatching Triage** ✅ | https://hatching.io · https://tria.ge | **Commercial**, volume-based licence ("priced on request") | **REST API** + UI; no MCP found ❌ | Automated sandbox for files/URLs, Windows 7/10, Linux, Android, macOS; 100+ file types; config extraction; live VM takeover | ✅ active (commercial) | Paid. ⚠️ Cloud-only by default → sample egress. Only if a client already pays for it |
| **MalwareBazaar (abuse.ch)** ✅ | https://bazaar.abuse.ch/api · endpoint `https://mb-api.abuse.ch/api/v1/` | Free, registration-based | **REST POST**, requires header **`Auth-Key: …`** (and `ABUSECH_AUTH_KEY` for `v2/files/exports/…/$KEY/full.csv.zip`) | Sample retrieval by hash, recent detections, tag info, full dumps (recent.csv every 5 min) | ✅ active | ⚠️ Auth-Key required since the abuse.ch lockdown; also sample downloads are **password-protected zips** (`infected`). Note the API is **POST-only** — a plain `GET /api` returns `405` (expected, not an outage). Wrap as our own `http` client; **no MCP found** |
| **MISP** ✅ | https://github.com/MISP/MISP · MCP: https://github.com/MISP/misp-mcp | Core **AGPL-3.0**; `misp-mcp` **no licence detected** ❌ | Core = REST API; `misp-mcp` = **MCP** (`pip install misp-mcp`) | Event/attribute/object search, event index, tags & taxonomies (TLP, kill chain), galaxies (threat actors, ATT&CK), feeds | Core ✅ pushed 2026-11-18, 6.7k★ · `misp-mcp` ⚠️ pushed 2026-06-26, 16★ | `misp-mcp` is **read-only by design** — good for safety, useless for pushing IOCs back. ⚠️ **No licence** on the MCP repo → don't vendor until clarified. MISP itself is AGPL → run as a service, not linked code |
| **speakeasy** ✅ | https://github.com/mandiant/speakeasy | **MIT** | Python API + CLI; no MCP | Windows **user + kernel-mode emulation** — defeats many anti-VM/anti-sandbox checks without a VM | ✅ pushed 2026-11-17, 2.1k★ | ✅ **Runs in a Linux container.** Very high value: API-behaviour emulation with no VM cost. CLI/JSON wrapper |
| **DRAKVUF** ✅ | https://github.com/tklengyel/drakvuf | ⚠️ NOASSERTION | C++ CLI/toolkit; no MCP | Black-box, **hypervisor-level (Xen)** dynamic analysis, stealthy | ✅ pushed 2026-11-02, 1.3k★ | ⚠️ **Requires Xen** + a Windows guest + LibVMI → dedicated host, out of scope for an MVP |
| **capa / FLOSS / YARA** | see §4 | Apache-2.0 / Apache-2.0 / BSD-3 | CLI | Static capability + string + rule triage | ✅ | These three are the **cheap, container-friendly** malware triage stack |

**Which already have MCP servers?** Official: **VirusTotal** (`virustotal-mcp`), **MISP** (`misp-mcp`). Third-party/unofficial:
**capa** (`capa-mcp`, `re-capa`, `rizin-mcp`), **Joern** (`joern-agent-bridge`, `codebadger`). **None** found for CAPE, Triage,
MalwareBazaar, speakeasy, DRAKVUF ❌ — but **all of those expose REST or CLI/JSON**, so they are straightforward wrappers.

---

## 6. Item 6 — Prior art, and what an ARTEX fork should copy

| System | Open source? | Architecture | Published results / lessons | What to copy |
| --- | --- | --- | --- | --- |
| **XBOW** ✅ | ❌ Closed (commercial) | Autonomous pentest platform, hosted; model-agnostic (they benchmark frontier models inside it) | Published a **public validation benchmark**: https://github.com/xbow-engineering/validation-benchmarks (**Apache-2.0**, 751★, 104 web-app CTF challenges, 3 difficulty tiers) — the de-facto yardstick. 2026-06 post: GPT-5.5-class models "rival Mythos" for vuln discovery | **Copy the benchmark, not the product.** Adopt the 104-challenge XBOW suite as ARTEX's regression harness for the 0day fork |
| **Strix** ✅ | ✅ **Apache-2.0** (https://github.com/usestrix/strix, 76.4k★, pushed 2026-11-17, PyPI `strix-agent`) | **Multi-agent graph**, agents run in a **Docker sandbox**, dynamic exploitation with real PoCs, **custom Python exploit runtime**, **pluggable MCP servers** via `~/.strix/mcp-servers.json` (stdio + http, namespaced `name_tool`, with tool filtering) | Positioned on **low false positives through live exploit validation** (vs static scanners). Scored **96.15 % (100/104)** on XBOW benchmarks in black-box mode (third-party comparison ⚠️) | **Closest architectural sibling to what we want.** Copy: (a) sandbox-per-session, (b) small agent graph + handoff, (c) per-run MCP server allow-list with tool filtering, (d) "validate with a PoC or drop the finding" gate |
| **Shannon** (KeygraphHQ) ✅ | ✅ **AGPL-3.0** (https://github.com/KeygraphHQ/shannon, 52.0k★, pushed 2026-11-16) | White-box: source analysis → attack-vector identification → **executes real exploits** | 96.15 % (100/104) XBOW, **white-box** mode ⚠️ (not comparable to black-box) | Copy the **source→vector→exploit** chain; note the white-box caveat so we don't over-claim |
| **CAI** (Cybersecurity AI) ✅ | ✅ repo, **but ARCHIVED 2026-08-22** (https://github.com/aliasrobotics/cai, 9.9k★) | Agent framework for security tasks | Archived → no upstream fixes | ❌ **Do not build on it.** Cite as prior art only |
| **PentestGPT** ✅ | ✅ **MIT** (https://github.com/GreyDGL/PentestGPT, 16.5k★, pushed 2026-07-14) | Reasoning/generation/parsing loop over pentest subtasks | Proved LLM-driven pentest planning works; weak at long-horizon state | Copy the **task-tree + explicit "what do I not know yet" prompt**; superseded architecturally by graph-based designs |
| **Vulnhuntr** ✅ | ✅ **AGPL-3.0** (https://github.com/protectai/vulnhuntr, 2.8k★, **last push 2025-02-06**) | Zero-shot: LLM traces user-controlled input from entrypoints → sinks in Python repos | Dormant for ~21 months | ❌ **Do not depend on it.** Copy only the *entrypoint→sink taint-prompt* idea (and prefer CodeQL/Joern for the real dataflow) |
| **Google Big Sleep / Naptime** ✅ | ❌ Closed | Per Project Zero's Naptime write-up: model gets a **code browser**, a **debugger**, a **Python sandbox**, and a **reporter tool** — i.e. an explicit toolbelt mirroring a human researcher | First real-world find announced 2024-11-01 (SQLite); 2025-07: used to find a SQLite flaw **attackers were about to exploit**; motivated by **variant analysis** at scale | Copy the **four-tool toolbelt minimalism** and the **variant-analysis** objective function (find more instances of a known bug class) |
| **OpenAI Aardvark** ✅ | ❌ Closed, **private beta** (announced 2025-10; GPT-5) | Agentic: reads code, semantic analysis, **writes and executes test cases to validate**, then patches; continuously scans repos | Reported high recall on known + synthetic vulns; "previously undetected issues" in early deployments ⚠️ (vendor claims) | Copy the **mandatory validation step** (execution, not reasoning) and the "agent proposes a patch" end state |
| **ZeroPath** ✅ | ❌ Commercial | AI-native SAST + SCA + secrets; business-logic & broken-auth detection; PR review + autofix; on-prem option | Team plan **from $1,000/mo + $60/dev**; startup discounts up to 50 % | Pricing benchmark for "AI-native SAST" — useful for build-vs-buy in the fork's business case |
| **AIxCC — Team Atlanta "Atlantis"** ✅ | ✅ https://github.com/Team-Atlanta/aixcc-afc-atlantis (664★; GitHub licence **NOASSERTION** ⚠️; reportedly MIT) | LLM + **symbolic execution** hybrid; 46-author technical report | **1st place, $4M**, DEF CON 33 final (results 2025-08-08). Across all 7 finalists: **54 of 63 planted bugs + 18 real bugs** found, most patched | ⭐ **The single most important architectural lesson:** LLM for *understanding*, **symbolic execution/fuzzing for proof**. Copy the hybrid and the "crash→root-cause→patch" loop |
| **AIxCC — Trail of Bits "Buttercup"** ✅ | ✅ **AGPL-3.0** (https://github.com/trailofbits/buttercup, 1.8k★, pushed 2026-11-02) | Multi-agent + program analysis | **2nd, $3M** | ⚠️ AGPL — read for design, don't link code |
| **AIxCC — Theori "RoboDuck"** ✅ | ⚠️ released, repo path **not verified this pass** ❌ | — | **3rd, $1.5M** | Ask team to confirm the repo URL before citing |
| **ReVa** ✅ | ✅ Apache-2.0 | Ghidra MCP with **many small tools**, schema tolerance, corrective nudges, xref/namespace context | Explicitly targets **context rot**; handles firmware-scale binaries | ⭐ **Copy the tool-design philosophy:** small tools, tolerant schemas, *return extra context (xrefs, namespace) to steer the next step* |

### Cross-cutting lessons for the ARTEX fork

1. **Validation is the differentiator, not detection.** Every credible system (Strix, Aardvark, AIxCC winners) *executes*
   something to prove the bug. A pure-LLM "I think this is a bug" report is a false-positive generator. ARTEX already has the
   right hook: the pre-seeded `retester` agent.
2. **Sandbox is non-negotiable** — Strix ships a Docker sandbox as the default execution model; AIxCC systems ran in
   instrumented sandboxes. For us: sandbox-per-engagement, and the MCP servers that *execute* (debuggers, `py_eval`,
   `browser_run_code_unsafe`, `patch_asm`) must be gated separately from read-only ones.
3. **Context budget is the real bottleneck.** 209-tool Ghidra servers and 63-tool CDP servers will blow the tool-schema
   budget. Both Strix (tool filtering) and ReVa (small tools) solve this. ARTEX's `ToolSet` must support **per-agent tool
   allow-lists and lazy tool loading**.
4. **False-positive rates are the published blocker** — everyone claims low FPs *because* of validation; nobody publishes
   clean precision numbers ⚠️. Treat any vendor FP claim as unverified.
5. **Cost is driven by trajectory length**, and the fix is graph-scoped work (planner/worker split) — which ARTEX already has.

---

## 7. Recommended integration set

Design constraints from ARTEX itself (verified in this repo): MCP client supports **`stdio` / `http` (Streamable HTTP) /
`sse`**, with the `env` map doubling as **HTTP headers** and an `insecure` TLS flag
([`server/mcpdiscover.go`](../../server/mcpdiscover.go)); agent execution already runs in a Docker image that ships
playwright/chromium and nmap, with `SKIP_PLAYWRIGHT=1` to slim it ([README](../../README.md)); tool calls pass a
`guard/intercept` approval gate; the planner/worker dual-graph architecture and the `retester` agent are the natural places
to attach new capability.

### MVP (ship first — all free, all container-friendly, all reversible)

| # | Integration | Transport in ARTEX | Why it makes the cut |
| --- | --- | --- | --- |
| 1 | **radare2-mcp** (`r2pm -Uci r2mcp`, Docker image available) | `stdio` (`r2pm -r r2mcp`) or `http` (`r2mcp -H 8765 -a <token>`) | Free, MIT, headless, one binary, already has **read-only mode + tool allow/deny + approval semantics** — matches our guard model. Gives the fork real binary RE on day one with **zero licence cost** |
| 2 | **Ghidra headless** (`analyzeHeadless`) wrapped as our **own** MCP tool | `stdio` (our wrapper) | Apache-2.0, containerisable, batch-decompile/export. Free decompiler at scale; complements r2 |
| 3 | **YARA + capa + FLOSS + DIE** as **one** `triage` MCP server we write | `stdio` | Four CLI/JSON tools behind one small interface; no official MCP needed. This is the cheapest 0day/malware triage win |
| 4 | **playwright-mcp** (`npx @playwright/mcp@latest`, already in the image) | `stdio` or `http` (`--port 8931`) | Cookies + localStorage/sessionStorage CRUD, `browser_route` interception, `browser_evaluate` — the core of client-side/auth-logic research. Apache-2.0, no egress |
| 5 | **VirusTotal official MCP** (`https://ai.virustotal.com/mcp`, OAuth) | `http` | Free VTAI tier, no local process, no API key. Instant IOC enrichment for the asset graph |
| 6 | **Semgrep CE via `semgrep --json`** wrapped as a tool | `stdio` (our wrapper) | Avoid the paid hosted MCP entirely; LGPL CLI is fine as a separate process |

**MVP deliberate omissions:** IDA (licence + GUI), Binary Ninja (licence + GUI-hosted MCP), CodeQL (licence), any sandbox
(infrastructure), browser-use (egress).

### v2 (after MVP is measured against XBOW's 104-challenge benchmark)

| # | Integration | Transport | Rationale |
| --- | --- | --- | --- |
| 7 | **`idalib-mcp`** from mrexodia's repo (or the **official HexRaysSA/ida-mcp**) | `stdio` (`uv run idalib-mcp --stdio --max-workers 4`) | The best decompiler, *headless* and session-per-database. **Pending an IDA Pro licence + IDA 8.3+/9.4+**. Prefer the official one for longevity; keep mrexodia's as fallback |
| 8 | **angr** (+ optionally **Triton**) as a `symbolic` MCP server | `stdio` | BSD-2 / Apache-2, free commercial, container-friendly. This is the **AIxCC lesson**: LLM understands, symbolic execution proves |
| 9 | **Joern** (or the `joern-agent-bridge`) | `stdio`/`http` | Apache-2 CPG dataflow → answers "does input reach sink" without burning context on source |
| 10 | **speakeasy** | `stdio` (CLI wrapper) | MIT, **emulates Windows malware in a Linux container** — huge capability jump with no VM |
| 11 | **CAPE v2 REST wrapper** (existing capesandbox.com demo or client-hosted) | `http` | Real dynamic analysis incl. unpacking/config extraction. Remote-only by nature |
| 12 | **MISP MCP** (`misp-mcp`, read-only) | `stdio` | Free IOC context — **after** the missing-licence issue is resolved |
| 13 | **chrome-devtools-mcp** | `stdio` | Only if web targets need **traces/heap/Lighthouse**; must ship `--no-usage-statistics --no-performance-crux` |

### Later / evaluate-only

- **Binary Ninja 6 native MCP** — technically nice, but **GUI-hosted HTTP** + per-seat cost makes it a poor server-side fit.
  Revisit only if analysts demand BN, and then use the headless Python API rather than its MCP.
- **bethington/ghidra-mcp** — 209 tools; only after we have per-agent tool allow-lists, otherwise it poisons the context.
- **ReVa** — its *tool design* is worth copying into our own Ghidra wrapper immediately; the extension itself is desktop-only.
- **RevEng.AI** — genuinely attractive for stripped-binary triage, but cloud upload + opaque pricing. Get a quote first;
  prefer on-prem/VPC if a client's samples are sensitive.
- **Hatching Triage / DRAKVUF / syzkaller** — infrastructure-heavy or paid; not for this fork's first year.

### Explicit exclusions (with reasons)

| Excluded | Why |
| --- | --- |
| **Cuckoo Sandbox** | Archived since **2022-05-03**. Dead code, no security fixes |
| **aliasrobotics/cai** | **Archived 2026-08-22** |
| **protectai/vulnhuntr** | Dormant since **2025-02-06**; AGPL |
| **puppeteer MCP** | Strictly dominated by playwright-mcp / chrome-devtools-mcp |
| **Semgrep hosted MCP** | Requires paid **Teams/Enterprise** plan; we lose nothing by using the CE CLI |
| **tree-sitter / FuzzingBook as "integrations"** | A library and a book, not callable tools |
| **`semgrep/mcp` standalone repo** | Archived 2025-10-28; do not pin to it |
| **BinAssistMCP** | Marked **planned archival**; native BN MCP supersedes it |
| **IDA GUI plugin + `localhost:13337/mcp`** | Deprecated by its own author; incompatible with headless workers |
| **Miasm (linked)** | GPL-2.0 — only ever as an isolated process, never linked |
| **Bundling any scanner into an always-on agent** | These tools are *capability*, not *policy*: every execute/patch/write tool must sit behind `guard/intercept` |

---

## 8. Unverified / must-check-before-committing

| Item | Status | What to do |
| --- | --- | --- |
| Theori **RoboDuck** repo URL | ❌ not verified this pass | Confirm the canonical GitHub path before citing in the fork's docs |
| **CAPE v2** licence | ⚠️ GitHub API reports `NOASSERTION` | Read `LICENSE` before shipping CAPE-derived code |
| **MISP/misp-mcp** licence | ❌ none detected on the repo | Do not vendor until clarified; call it as a service |
| **Atlantis** licence | ⚠️ `NOASSERTION` on GitHub API; third parties report MIT | Confirm `LICENSE` file before reuse |
| **ql-mcp** licence | ⚠️ `NOASSERTION` | Legal review; CodeQL CLI itself is restricted for closed-source use |
| **CodeQL `ql-mcp` Node 25.6+** | ⚠️ quoted from its README; unusually specific | Re-read at install time |
| Puppeteer MCP canonical repo | ❌ not re-verified | Only matters if we break the "skip" decision |
| **RevEng.AI** free tier / pricing, MCP availability | ❌ no public price; **no MCP server found** | Request quote + ask about on-prem; assume a thin REST wrapper is needed |
| VT free VTAI rate limits | ⚠️ "current access limits", unspecified | Measure at integration time; assume low |
| Third-party benchmark numbers (Strix 96.15 %, Shannon 96.15 %) | ⚠️ from a third-party comparison doc, not vendor-published | Re-run ourselves on the 104-challenge suite before publishing any claim |
| **AIxCC** "18 real bugs" breakdown | ⚠️ aggregate across 7 finalists | Read the technical report before quoting per-team |
| WebSocket **frame** capture in browser MCP servers | ⚠️ no dedicated tool in either server | Would need a small custom CDP shim (`Network.webSocketFrameReceived`) |
| Star counts / `pushed_at` | snapshot **2026-11-18** | Refresh if this doc is used after ~2027-02 |
| Project Zero **Naptime** post URL | ⚠️ canonical URL, but fetch was blocked from this environment (`000`) | Open `https://googleprojectzero.blogspot.com/2024/06/project-naptime.html` manually before citing; the search-result mirror corroborates the four-tool description |
| **Aardvark** announcement URL | ⚠️ `openai.com` returned **403** to automated fetch (bot block) | URL is believed canonical; verify in a browser before external publication |

---

## 9. Sources

**Item 1** — [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) · [HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp) · [Hex-Rays announcement](https://hex-rays.com/blog/hex-rays-ida-mcp-server) · [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) · [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) · [cyberkaida/reverse-engineering-assistant](https://github.com/cyberkaida/reverse-engineering-assistant) · [symgraph/GhidrAssistMCP](https://github.com/symgraph/GhidrAssistMCP) · [symgraph/BinAssistMCP](https://github.com/symgraph/BinAssistMCP) · [Binary Ninja MCP docs](https://docs.binary.ninja/guide/mcp.html) · [BN 6.0 release](https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html)

**Item 2** — [reveng.ai](https://reveng.ai/) · [RevEngAI/sdk-typescript](https://github.com/RevEngAI/sdk-typescript) · [PyPI `rea`](https://pypi.org/project/rea/) · [npm `rea`](https://registry.npmjs.org/rea) · [radareorg/radare2-mcp](https://github.com/radareorg/radare2-mcp) · [Zfinix/eleven](https://github.com/Zfinix/eleven)

**Item 3** — [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) + [tool reference](https://github.com/ChromeDevTools/chrome-devtools-mcp/blob/main/docs/tool-reference.md) · [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) · [browser-use/browser-use](https://github.com/browser-use/browser-use)

**Item 4** — [semgrep](https://github.com/semgrep/semgrep) + [MCP docs](https://docs.semgrep.dev/mcp/overview) + [archived semgrep/mcp](https://github.com/semgrep/mcp) · [github/codeql](https://github.com/github/codeql) + [codeql-development-mcp-server](https://github.com/advanced-security/codeql-development-mcp-server) · [joern](https://github.com/joernio/joern) + [joern-agent-bridge](https://github.com/epi13/joern-agent-bridge) · [tree-sitter](https://github.com/tree-sitter/tree-sitter) · [angr](https://github.com/angr/angr) · [Triton](https://github.com/JonathanSalwan/Triton) · [Miasm](https://github.com/cea-sec/miasm) · [capa](https://github.com/mandiant/capa) · [YARA](https://github.com/VirusTotal/yara) · [FLOSS](https://github.com/mandiant/flare-floss) · [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) · [Ghidra](https://github.com/NationalSecurityAgency/ghidra) · [cwe_checker](https://github.com/fkie-cad/cwe_checker) · [syzkaller](https://github.com/google/syzkaller)

**Item 5** — [VirusTotal/virustotal-mcp](https://github.com/VirusTotal/virustotal-mcp) · [VT API v3](https://docs.virustotal.com/reference) · [CAPEv2](https://github.com/kevoreilly/CAPEv2) + [docs](https://capev2.readthedocs.io) · [Cuckoo (archived)](https://github.com/cuckoosandbox/cuckoo) · [Hatching Triage](https://hatching.io) · [MalwareBazaar API](https://bazaar.abuse.ch/api) · [MISP](https://github.com/MISP/MISP) + [misp-mcp](https://github.com/MISP/misp-mcp) · [speakeasy](https://github.com/mandiant/speakeasy) · [DRAKVUF](https://github.com/tklengyel/drakvuf) · capa MCP: [FuzzingLabs/mcp-security-hub](https://github.com/FuzzingLabs/mcp-security-hub), [Heretek-RE/re-capa](https://github.com/Heretek-RE/re-capa)

**Item 6** — [XBOW validation benchmarks](https://github.com/xbow-engineering/validation-benchmarks) · [XBOW blog](https://xbow.com/blog/gpt-5-5-and-xbow-a-step-change-in-autonomous-application-security) · [usestrix/strix](https://github.com/usestrix/strix) · [KeygraphHQ/shannon](https://github.com/KeygraphHQ/shannon) · [aliasrobotics/cai (archived)](https://github.com/aliasrobotics/cai) · [GreyDGL/PentestGPT](https://github.com/GreyDGL/PentestGPT) · [protectai/vulnhuntr](https://github.com/protectai/vulnhuntr) · [Project Naptime / Big Sleep](https://googleprojectzero.blogspot.com/2024/06/project-naptime.html) · [OpenAI Aardvark](https://openai.com/index/introducing-aardvark/) · [ZeroPath pricing](https://zeropath.com/pricing) · [Team-Atlanta/aixcc-afc-atlantis](https://github.com/Team-Atlanta/aixcc-afc-atlantis) · [trailofbits/buttercup](https://github.com/trailofbits/buttercup)
