# ARTEX architecture & extension-point map (for the secondary-development fork)

Scope: the checkout at 本仓库根目录, read-only inspection of source
(no `.git` present in this copy, so no commit hash). Every claim below cites `file:line`
in this checkout. Paths are relative to the repo root.

Size: 93,282 lines of Go (63,204 non-test) + 56,088 lines of TS/TSX under `web/src`.
Go packages by size (non-test): `server` 25.1k, `db` 19.6k, `agent` 7.4k, `notify` 2.6k,
`traffic` 2.5k, `intercept` 1.2k, `selfupdate` 1.0k, `sidequestion` 0.8k, `mcphttp` 0.6k,
`llmrec` 0.6k, `llmpool` 0.5k, `evidence` 0.4k, `report` 0.3k, `enrich` 0.3k, `guard` 0.2k,
`config` 0.2k, `cmd/artex` 0.16k.

Dependency of record: `github.com/Autumn-27/norma v0.4.3` (`go.mod:6`) — the agent runtime,
tool contract, skill loader, MCP stdio client, hooks, permission model, transcript and
compaction all live in that module, **not** in this repo. Its source is only available from the
module cache: Go module cache 里的 `norma@v0.4.3` (cited below as
`norma@v0.4.3/...`). Any fork that needs to change agent-loop/tool-contract semantics must
either vendor this module (`go mod vendor`) or fork it.

---

## 1. Agent model

### 1.1 The agent "keys" that exist

Agent identity is a row in `agents` (`db/schema.sql:766-796`). `key` is
`^[a-z][a-z0-9_]*$` (`db/schema.sql:768`), `role` is constrained to
`goals | main | planner | worker | assistant` (`db/schema.sql:789`). `builtin` distinguishes
code-seeded agents from user-created ones.

Code-seeded built-ins (`db/db.go:191-214`, struct `builtinAgent` at `db/db.go:188`):

| key | name | role | notes |
|---|---|---|---|
| `goals` | 目标拆解 | goals | one-shot goal decomposer; `interactive_shell=false` (`db/db.go:192`) |
| `planner` | 规划 | planner | per-task planning rounds (`db/db.go:197`) |
| `mainagent` | 主 | main | human interface into a task (`db/db.go:201`) |
| `worker` | 执行 | worker | executes one intent (`db/db.go:206`) |
| `auto` | Auto | assistant | chat-driven platform operator; tools = list/spawn/pause/hint + skill/custom-tool/MCP management (`db/db.go:211`) |
| `pentest` | 渗透测试 | assistant | standalone solo pentest agent, interactive shell on, `run_seconds=0` (`db/db.go:213`) |

Seeded elsewhere (not in the `builtinAgents` table):

- `reporter` (报告撰写, role assistant, `builtin=false`) — created by `seedReporterAgent`
  (`server/orchestration.go:735-780`), fired by a `report_finding` tool-call trigger.
- `retester` (`db.FindingRetestAgentKey`, `db/finding_retests.go:13`) — created by
  `seedFindingRetester` (`server/finding_retests.go:194-235`).
- Arbitrary custom agents created from the UI: `CreateAgent` hardcodes
  `role='assistant', builtin=false` (`db/config.go:558-569`), handler
  `pgCreateAgent` (`server/server_mgmt.go:246-279`), key regex `reAgentKey`
  (`server/server_mgmt.go:65`).

### 1.2 Where keys are registered and what a key actually selects

Registration is **DB seeding**, idempotent, run on every boot:
`Open` → `withSchemaMigrationLock` → `applySchemaWithRetry` + `seedBuiltins`
(`db/db.go:157-171`). `seedBuiltins` does
`INSERT ... ON CONFLICT (key) DO UPDATE SET name, description` (`db/db.go:217-240`), so renaming
a built-in agent in code renames it on upgrade but never touches prompts/tool bindings.

A key means two different things depending on the row's role:

1. **Orchestration roles** (`goals`/`planner`/`worker`/`mainagent`) are *fixed singletons* per
   task. `agentsForTask` builds exactly four runtimes with those four literals
   (`server/task_llm.go:552-582`), returning a `taskAgentBundle` (`server/task_llm.go:22-30`).
   The engine pulls them through `SetAuthoritativeAgentResolver`
   (`server/server.go:158-165`). Agent choice here is **not data-driven** — a new orchestration
   role requires code.
2. **Assistant roles** (`auto`, `pentest`, `reporter`, `retester`, custom) are *chat* agents:
   `agent.ChatAgent` (`agent/chat.go:25-38`) is key-agnostic; it renders the prompt for that key
   (`chatSystem`, `agent/chat.go:86-89`), uses `actool.DefaultTools()` as base and relies on
   `AugmentTools` for skills/MCP (`agent/chat.go:120-126`). They are driven by
   conversations (`server/conversations.go`) and the P3 trigger scheduler
   (`StartTriggeredRun`, `server/conversations.go:610-620`; `runTriggeredRun` builds a synthetic
   conversation). This is the data-driven path: add a row + prompt + tool bindings and a new
   assistant agent exists.

Per-agent knobs live as columns on `agents`: `llm_profile_id`, `max_turns`, `run_seconds`,
`web_search`, `interactive_shell`, `wrapup_prompt`, `wrapup_max_turns`,
`task_timeout_wrapup_prompt`, `task_timeout_wrapup_max_turns`, `trigger_run_mode`,
`trigger_merge_mode`, `trigger_max_parallel` (`db/schema.sql:766-789`). They are edited via
`PUT /api/agents/{key}/config` (`server/server.go:840`) and read at run time
(`server/server.go:298` `agentMaxTurns`, `:311` `agentRunSeconds`).

### 1.3 How prompts are composed

Two layers, and code-owned tails that a DB edit cannot remove:

1. **Editable body.** `renderSystem(agentKey, def, vars)` (`agent/prompt.go:29-52`): if
   `PromptOverride` is wired (`agent/prompt.go:11`, wired at `server/server.go:190-198` to
   `agent_prompts` via `CurrentPrompt`) it renders that; otherwise the in-code default. Both are
   Go `text/template` with `Option("missingkey=error")`; a broken user template falls back to the
   code default, then to the raw string (`agent/prompt.go:41-51`).
   Default bodies: `BuiltinPromptSeeds()` (`agent/promptcatalog.go:113-121`) maps
   `goals/planner/mainagent/worker/auto/pentest` → template strings defined in the same file
   (`goalsDefaultTmpl` … `pentestDefaultTmpl`). One-shot starters:
   `DefaultAssistantPrompt` (`agent/promptcatalog.go:70`), `ReporterDefaultPrompt`
   (`agent/promptcatalog.go:76`), `RetesterDefaultPrompt`.
   Seeding is first-insert-only: `server/assembly.go:194-210` → `SeedPromptIfEmpty`.
   Version history is `agent_prompts` (`db/schema.sql:804-818`), pointer
   `agents.current_prompt_id` (`db/schema.sql:797-802`).
2. **Template variables.** One Go struct per built-in role (`agent/prompt.go:19-22`:
   `PlannerVars`, `WorkerVars`, `MainVars`, `GoalsVars`), chat agents get `chatVars{DataDir,Now}`
   (`agent/chat.go:94`). `{{.Now}}` is universal (`agent/prompt.go:27`). The variable *catalog*
   shown in the UI is DB data: `agent_prompt_vars` (`db/schema.sql:820-831`), seeded per agent by
   `seedBuiltins` (`db/db.go:228-240`), served by `GET /api/agents/{key}/variables`
   (`server/server.go:852`). A template referencing a var absent from the struct fails to render
   and silently falls back to the built-in default — this is the most common "my prompt edit was
   ignored" failure mode.
3. **Code-owned tails** appended after the body:
   - planner: `artifactSpec(workDir)` (`agent/planner.go:342-345`)
   - worker: `workerSystem` + `constraintBlock` + `renderIntentTask` + intent-anchored asset JSON
     + start directive (`agent/worker.go:396-420`)
   - mainagent: `mainAgentSystem` (`agent/mainagent.go:103`), chat: `chatWorkDirSpec`
     (`agent/chat.go:80-84`)
   - deferred-tool block as the **last cached segment**, with `DynamicBoundary` set
     (`agent/deferred.go:20-31`).
   - wrap-up/settlement prompts are separately DB-overridable (`WrapupOverride` …
     `WrapupTaskTimeoutTurnsOverride`, `server/server.go:199-215`; agent rows hold
     `wrapup_*` columns).

### 1.4 Per-agent tool binding: DB rows, code seeds

Binding is a DB fact: `tools.agents` is a JSONB array of agent keys
(`db/schema.sql:935-949`; struct `db.Tool` at `db/tools.go:12-23`). Code provides only the
*defaults*:

- `BuiltinToolSeeds()` (`agent/toolcatalog.go:63-100`) walks the per-agent domain tool sets
  (`builtinToolsByAgent`, `agent/toolcatalog.go:34-53`) and emits `{Key, Desc, Schema, Agents}`
  per tool. `defaultUnbound` (`agent/toolcatalog.go:59`) forces empty bindings for risky tools
  (`goal_met`).
- The SDK tools (Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash/Sleep) are **deliberately not
  seeded** — every agent always has them, so they have no row and no binding; see the comment at
  `agent/toolcatalog.go:29-38`.
- Host tools are seeded with their own defaults: traffic tools → `["worker"]`
  (`server/assembly.go:228-237`), orchestration tools → `["auto"]`
  (`server/orchestration.go:476-483`), platform tools → `["auto"]`
  (`server/orchestration.go:485-488`), finding-traffic readers → `["auto","reporter"]` and
  rebinding migrations (`server/finding_workflow.go:88-105`).
- Visibility of *MCP servers* and *skills* is a separate pair of tables:
  `agent_visibility(resource_kind='mcp', resource_id, mcp_tool_name)` and
  `agent_skill_visibility(skill_name)` (`db/schema.sql:877-897`), edited through
  `PUT /api/agents/{key}/visibility` (`server/server.go:855`, handler
  `server/server_mgmt.go:717-737`).

Runtime application order: base tools → `ToolAugment` (skills + MCP + host tools) →
`ToolResolve` (DB filter/inject/override, `agent.ToolResolve` declared at
`agent/toolcatalog.go:107`, implemented at `server/assembly.go:239-330`) →
`findingWorkflowTools` guidance → panic guard (`agent/assembly.go:39-74`).

### 1.5 How a new agent type would be added

Two shapes, different cost:

- **New assistant/chat agent (e.g. `researcher`, `binanalyst` as chat-driven specialists)** —
  no engine change. Add a seed row (or create it in the UI), a prompt default, default tool
  bindings, optional MCP/skill visibility, optional trigger rows. Details in §10(a).
- **New orchestration role** (an agent that participates in the task loop, with its own turn
  driver and `agentcore.Options`) — requires a new runner in `agent/`, a new key literal in
  `agentsForTask`/`taskAgentBundle` (`server/task_llm.go:22-30,552-582`), a new entry in
  `BuiltinPromptSeeds` (`agent/promptcatalog.go:113`), a var struct+render call
  (`agent/prompt.go`), a tool-set function (`agent/tools.go` style) and engine scheduling
  (`server/engine.go`). High cost; recommend only if the new domain needs its own
  claim/execute/write-back loop.

---

## 2. Tool system

### 2.1 The contract

`CoreTool` (`norma@v0.4.3/tool/tool.go:85-95`) requires:
`Name() string`, `Description() string`, `Prompt() string`, `InputSchema() map[string]any`,
`IsReadOnly(input) bool`, `IsConcurrencySafe(input) bool`,
`CheckPermissions(ctx, input, permission.Context) permission.Decision`,
`Call(ctx, input, *ToolContext) (Result, error)`.

Tools are constructed with `actool.Build(Spec{...})` (`norma@v0.4.3/tool/tool.go:96-160`),
which applies **fail-closed** defaults: `ReadOnly`/`Concurrent` nil ⇒ `false`; `Permissions` nil ⇒
`permission.AskUser` (i.e. an approval prompt, not a silent allow). `Spec.RawInput` skips schema
validation for tools that repair their own args.

`Result` carries `Content []llm.ContentBlock`, `IsError bool`, and `Extra []llm.Message`
(`norma@v0.4.3/tool/tool.go:55-68`) — the `Extra` channel is how the `Skill` tool injects
instructions as a standalone user message rather than burying them in a tool_result.

Core SDK toolset every agent gets: `DefaultTools()` = Read, Write, Edit, MultiEdit, LS, Glob,
Grep, Bash, Sleep (`norma@v0.4.3/tool/registry.go:62-67`). Network/stateful tools (WebFetch,
TodoWrite) are opt-in via `agentcore.Options`.

### 2.2 ARTEX domain tools

All ARTEX-owned tools are built inside `agent.ToolSet` (`agent/tools.go:53-112`) — a struct that
holds the stores (`*db.AssetStore`, `*db.CompanyStore`, `*db.ExplorationStore`), the task id,
write counters and engine callbacks. Tools are plain methods returning `actool.CoreTool`:

- helpers `readTool` (`agent/tools.go:280-291`) and `writeTool` (`agent/tools.go:292-308`) both
  return `Permissions: Allowed()` (they bypass the SDK approval layer; safety comes from the
  guard/intercept layer instead — §5). `readTool` additionally sets read-only + concurrency-safe.
- `readExpTool`/`writeExpTool` (`agent/tools.go:310-330`) wrap handlers with a nil-store guard so
  a mis-bound graph tool returns a message instead of nil-derefing (panic protection across the
  harness goroutine).
- **Tool groups are Go functions**, not a declared concept:
  `MainAgentTools()` (`agent/tools_insert.go:664-685`), `PlannerTools()`
  (`agent/tools.go:2033-2053`), `WorkerTools()` (`agent/tools_insert.go:644-662`),
  `AllDomainTools()` (union, used to build the server-level registry,
  `agent/tools_insert.go:688-699`).
- Domain tools present: graph/facts/findings (`graph_overview`, `list_findings`, `list_facts`,
  `node_detail`, `expand_digest`), intents/goals/constraints (`add_intent`, `prove_goal`,
  `goal_met`, `set_goals`, `set_constraints`, `add_task_hint`), writes (`report_finding`,
  `record_fact`, `insert_assets`), asset ops (`list_assets`, `list_companies`,
  `add_company_scope`, `add_task_scope`, `list_untested_assets`), worker control
  (`kill_work`, `steer_work`), trace readback (`get_worker_output`, `get_worker_trace`,
  `list_worker_traces`, `search_all_worker_traces`).

### 2.3 Where the DB overrides tools

`tools` table (`db/schema.sql:935-949`): `key` PK, `system`, `description`, `schema` JSONB,
`agents` JSONB, `enabled`, `kind` (`builtin|command|script|http|shell`), `exec` JSONB,
`deferred`. `kind` has no CHECK constraint; values are validated in handlers
(`server/customtool.go:61,103`).

- Seeding: `SeedTool` is `ON CONFLICT DO NOTHING` (`db/tools.go:31-46`) — UI edits survive
  restarts; `UpsertToolForce` (reset), `RefreshToolDefaults`, `SeedTool`-then-migrate patterns
  (`server/orchestration.go:489-508`, `server/finding_workflow.go`) handle schema upgrades.
- Runtime filtering/overriding: `agent.ToolResolve` (`server/assembly.go:239-330`):
  1. reads all rows, drops tools that are `!Enabled` or whose `agents` lacks this key
     (`server/assembly.go:257-268`);
  2. decorates survivors so the model sees the DB `description`/`schema` and gets scalar
     `default` values injected when omitted (`agent.DecorateTool`/`injectDefaults`,
     `agent/toolcatalog.go:113-190`);
  3. **injects** domain tools bound to the agent but absent from the incoming list, using a
     server-level registry with a nil ExplorationStore (`server/assembly.go:269-288`,
     `buildDomainReg` `server/assembly.go:346-360`) — this is how `auto`/custom agents get
     domain tools;
  4. `kind='shell'` rows are *not tools*: they are environment declarations appended to Bash's
     description (`server/assembly.go:290-307`);
  5. `interactive_shell` agents get `actool.ShellSessionTools()` injected + a Bash addendum
     (`server/assembly.go:308-323`).
- Tools with no DB row (MCP, skill meta-tool, host tools when unseeded) pass through untouched
  (`server/assembly.go:259-263`).

Host tools layered per run: `hostTools()` (`server/orchestration.go:40-66`) = traffic tools +
orchestration tools + finding-retest tools + platform tools + user custom tools. Custom tools are
built from DB rows into CoreTools by `buildCustomTool` (`server/customtool.go:265-300`); a
`deferred=true` custom tool has its schema withheld and is routed through
`SearchExtraTools`/`ExecuteExtraTool` (`server/assembly.go:151-168`).

### 2.4 What it takes to add a new built-in tool group

See §10(b). In short: a `func (t *ToolSet) XxxTools() []actool.CoreTool` in `agent/`, an entry in
`builtinToolsByAgent()` (`agent/toolcatalog.go:34-53`) so it gets seeded/bindable, wiring into the
relevant `AugmentTools` base list (`agent/worker.go:376-379`, `agent/planner.go:375`,
`agent/mainagent.go:127`, `agent/chat.go:121`), and (for non-task agents) inclusion in
`AllDomainTools`/`buildDomainReg`. Nothing in the SDK must change.

---

## 3. MCP integration

### 3.1 Transports and clients

| transport | client | code |
|---|---|---|
| `stdio` | norma `mcp.NewStdioClient(ctx, name, command, env, args...)` | `server/mcpdiscover.go:31-34` |
| `http` (Streamable HTTP, `application/json` or SSE response, protocol `2025-06-18`) | `mcphttp.New` | `mcphttp/client.go:99-122`, protocol const `mcphttp/client.go:31` |
| `sse` (legacy GET /sse + POST /message, `2024-11-05`) | `mcphttp.NewSSE` | `mcphttp/client.go:124-180`, const `mcphttp/client.go:32` |

`mcphttp` exists precisely because "the core mcp package only speaks stdio"
(`mcphttp/client.go:1-9`). Custom headers come from the MCP row's `env` map, so
`{"Authorization":"Bearer …"}` is how auth is configured (`mcphttp/client.go:3-7`,
`server/mcpdiscover.go:37-38`). `insecure: true` skips TLS verification for `http`
(`db/schema.sql:851`).

### 3.2 Tool naming and wrapper

`mcphttp.ToolName(server, name) = "mcp__" + server + "__" + name` (`mcphttp/client.go:35`).
`Client.Tools` calls `tools/list` and wraps each in a `CoreTool` (`mcphttp/client.go:258-330`):
the wrapper asks for user approval (`permission.AskUser`, `mcphttp/client.go:290-292`) and
`tools/call` results are truncated/spilled through `actool.Capture` like native tools
(`mcphttp/client.go:321`). `Client.Call` bypasses the permission wrapper for backend batch
jobs such as asset sync (`mcphttp/client.go:330-345`).

### 3.3 Data model

`mcp_servers` (`db/schema.sql:833-861`): `name` unique, `transport` CHECK
`('stdio','http','sse')`, `command`, `args` JSONB, `env` JSONB (also used as HTTP headers),
`url`, `enabled`, `insecure`. Struct `db.MCPServer` (`db/config.go:809-820`). Tool metadata cache
`mcp_tools_cache` (`db/schema.sql:864-875`) filled by discovery, so the UI lists tools without a
live connection. Per-agent/per-tool visibility: `agent_visibility` with
`resource_kind='mcp'`, `resource_id` = server id, `mcp_tool_name` (empty = whole server)
(`db/schema.sql:877-886`).

CRUD API: `GET/POST /api/mcp`, `DELETE /api/mcp/{id}`, `GET /api/mcp/{id}/tools`,
`POST /api/mcp/{id}/refresh` (`server/server.go:866-870`); handler `pgSaveMCP` auto-discovers
tools on create (`server/server_mgmt.go:863-891`). Discovery helpers: `connectMCP`
(`server/mcpdiscover.go:26-46`), `discoverAndCacheMCP` (`:48-67`),
`discoverEmptyMCPsOnStartup` (`:69-90`, launched at `server/server.go:236`).

### 3.4 How MCP tools surface, and the deferred/gating machinery

The single wiring point is `wireAgentAugment` (`server/assembly.go:25-192`), installed at
`server/server.go:220`. Per agent run it:

1. loads the agent's visible skills from disk into a `skill.Registry`
   (`server/assembly.go:37-60`);
2. treats any MCP server named in a visible skill's `mcps:` frontmatter as **skill-gated**
   (`server/assembly.go:61-71`);
3. connects every enabled server that is either directly visible (`agent_visibility`) or
   skill-gated (`server/assembly.go:73-125`);
4. splits the resulting tool names:
   - **global** = directly visible AND not gated → seeded into the `UnlockSet` at session start
     and rendered in the `<available-deferred-tools>` block (`server/assembly.go:115-120`);
   - **skill-gated** → withheld from the block until the skill is invoked; unlocked by
     `unlockSkill` (`server/assembly.go:128-145`).
5. Deferred mechanism itself comes from norma: `UnlockSet` (`norma@v0.4.3/tool/deferred.go:27-63`),
   `RenderDeferredToolsBlock` (`norma@v0.4.3/tool/deferred.go:78-100`), and the always-loaded
   access tools `SearchExtraTools` / `ExecuteExtraTool` (`norma@v0.4.3/tool/deferred.go:23-24,
   102, 221`). Deferred tools are callable but their schema is withheld to save context.
6. The host-side contract is `agent.DeferredInfo{FindingGuidance, Deferred, GlobalNames, Unlock,
   UnlockSkill}` (`agent/assembly.go:18-32`); the block is appended last with a cache boundary at
   `agent/deferred.go:20-31`; on resumed sessions skill-gated MCPs are re-unlocked by replaying
   prior `Skill` calls (`agent/deferred.go:34-51`, called from `agent/mainagent.go:194`,
   `agent/chat.go:182`).
7. Cleanup closes every spawned MCP client at run end (`server/assembly.go:170-176`).

### 3.5 The one existing auto-configured MCP (template for IDA Pro)

The `browser` (Playwright) MCP is seeded as `stdio` + `npx @playwright/mcp --headless`, disabled
by default (`db/db.go:255-266`; insert-if-absent). When traffic capture is toggled,
`Manager.syncBrowserMCPProxy` rewrites its `args`/`env` to append
`--proxy-server <recording proxy>` and `NODE_EXTRA_CA_CERTS <mitm CA>` (or strips them)
(`server/manager.go:635-690`, called from `server/manager.go:445,470,799`). This is the pattern
to copy for IDA Pro / RevEng.AI / a CDP server: seed row + a reconciler that mutates
`args`/`env` from platform state.

### 3.6 Registering a stdio MCP server "automatically per task"

Today visibility is **agent-scoped, not task-scoped** (`agent_visibility.agent_id`). The
assembly closure keyed by `agentKey` is invoked per run and *does* receive the run identity in
ctx — `agent.RunInfoFrom(ctx)` returns `{TaskID, ExplorationID, IntentID, SessionID}`
(`agent/runinfo.go:20-31`) — but `wireAgentAugment` currently only uses ctx for the skill usage
ledger (`server/assembly.go:140-146`). So per-task MCP injection is a ~30-line change: read
`RunInfoFrom(ctx).TaskID` inside `agent.ToolAugment` and filter the server list by a new
task↔server mapping table (e.g. `task_mcp_servers`), exactly where `want` is computed
(`server/assembly.go:75-82`). Details in §10(c).

---

## 4. Skills

### 4.1 Format

A skill is a directory `<skill_dir>/<name>/` containing `SKILL.md` with YAML frontmatter
following the agentskills.io spec. Parsing: `skill.parse` (`norma@v0.4.3/skill/skill.go:263-294`),
`frontmatter` struct (`:248-261`), `Skill` struct (`:28-44`).

Recognized keys: `name` (required), `description` (required), `license`, `compatibility`,
`whenToUse`/`when_to_use` (legacy), **`mcps`** (string or list; MCP servers this skill unlocks).
Body = instructions; `${SKILL_DIR}` inside the body is replaced with the absolute skill dir when
invoked (`norma@v0.4.3/skill/skill.go:133`). Discovery: `skill.LoadDir`
(`norma@v0.4.3/skill/skill.go:207-246`) accepts a subdirectory with `SKILL.md` or a bare `.md`
file; malformed YAML degrades to empty metadata instead of dropping the skill
(`:263-266`).

Shipped skills in-repo: `skills/api-recon` (SKILL.md + `scripts/` + `reference.md`),
`skills/playwright-cli` (SKILL.md + `references/`), `skills/scopesentry` (SKILL.md only).
Example frontmatter: `skills/api-recon/SKILL.md:1-4`.

Default visibility seed: `builtinSkillVisibility = {"api-recon": ["auto","pentest","worker"]}`
(`db/db.go:317-330`); `playwright-cli` and `scopesentry` ship invisible
(`db/db.go:321-323`, seed `db/db.go:331-345`).

### 4.2 How skills reach an agent

- Filesystem root: `config.SkillDir()` precedence `ARTEX_SKILL_DIR` > `config.json skill_dir` >
  `<exe dir>/skills` (`config/config.go:111-127`).
- Assignment: `agent_skill_visibility` rows (`db/schema.sql:888-897`), read by
  `AgentSkillNames` (`db/config.go:947-982`), written by `SetAgentSkillVisibility` /
  `ToggleSkillVisibility` (`db/config.go:983-1014`) via `PUT /api/agents/{key}/visibility`.
- At run time the visible skills are packed into **one meta-tool named `Skill`**
  (`skill.Registry.Tool`, `norma@v0.4.3/skill/skill.go:100-163`); invoking it emits the
  instructions as an `Extra` user message plus unlocks the skill's MCPs through
  `Registry.OnInvoke` (`server/assembly.go:126-145`).
- Usage ledger: `skill_usage` (`db/schema.sql:900-917`), `meterSkillTool`
  (`server/skill_usage.go:35-80`); misses (`found=false`) are recorded to drive skill backfill.

### 4.3 Management API and zip upload

`server/server.go:878-896`:

```
GET    /api/skills                     fsListSkills        server/server_mgmt.go:975
POST   /api/skills                     fsCreateSkill       server/server_mgmt.go:1075
POST   /api/skills/upload              fsUploadSkill       server/server_mgmt.go:1292
DELETE /api/skills/{name}              fsDeleteSkill
GET    /api/skills/missing             fsMissingSkills     (gap list from skill_usage)
GET    /api/skills/{name}/usage        fsSkillUsage
PUT    /api/skills/{name}/meta         fsUpdateSkillMeta   (edits YAML frontmatter)
POST   /api/skills/{name}/dirs         fsCreateDir
GET    /api/skills/{name}/files        fsListFiles
GET/PUT/DELETE /api/skills/{name}/files/{file...}
GET/POST /api/visibility/skill/...     agent_skill_visibility
```

Zip upload details (`server/skill_zip.go` + `server/server_mgmt.go:1292-1400`): 20 MB request cap,
100 MB total, 20 MB/file, 4000 entries (`server/server_mgmt.go:1257-1263`); extra decompressors
registered for bzip2 and zstd (Zip method 12/20/93) since Go's stdlib only handles Store/Deflate
(`server/skill_zip.go:22-82`, `.RegisterDecompressor` calls at `:61-82`); GBK entry names
decoded (`server/skill_zip.go:84-114`); zip-slip blocked by path validation; extraction goes to a temp dir then atomic rename; the skill name is
taken from `SKILL.md` `name:` frontmatter, falling back to top dir / zip name
(`skillNameFromFrontmatter`, `server/server_mgmt.go:1266-1289`); `?overwrite=true` replaces.

---

## 5. Safety layer: guard + intercept (and where scope enforcement plugs in)

### 5.1 guard

`guard` is the hook-based gate. Package doc (`guard/guard.go:1-7`) states explicitly: *"Every tool
call passes through the PreToolUse hook before executing. (The RoE authorization-scope mechanism
was removed; a replacement may be added later.) Destructive/exfil gating is no longer hard-coded
here — it lives in the DB intercept rules … evaluated via applyIntercept."*

- `Guard` holds an in-memory audit ring (`[]AuditEntry`, cap 2000, `guard/guard.go:21-37,181-188`),
  failure-attribution counters (`:34`), a `hook.Registry` (`:48-52`) and an optional
  `*intercept.Interceptor` (`:36`).
- `preToolUse` (`guard/guard.go:57-79`) extracts the command surface for Bash / `shell_open` /
  `shell_send`, records `allow` into the audit ring, then delegates to `applyIntercept`.
- `applyIntercept` (`guard/guard.go:83-124`) is the extension seam: skip if no interceptor or the
  tool is disabled (`IsToolEnabled`, `:87`); otherwise `Match(tool,input)` → first matching rule;
  if no rule matches, optional LLM fallback judge (`Judge`, `:95`); then dispatch on
  `allow | deny | ask`. `deny` logs and returns `hook.Result{Decision:"block"}`; `ask` blocks on
  `HandleAsk` (approval) unless ctx is already cancelled.
- Blocks are framed to the model as platform policy, not target defense
  (`systemBlockMessage`, `guard/guard.go:126-141`) — important: an agent must not treat a policy
  block as a WAF to bypass.
- `postToolUse` (`guard/guard.go:145-163`) classifies Bash results (`blocked|error|ok`) for
  failure attribution (Observer/G5).
- Where the guard is attached: per task `Task.Guard = guard.NewWithInterceptor(ic)`
  (`server/manager.go:849`), `Task.Guard.Hooks()` wrapped by `steerHooks`
  (`server/engine.go:1009-1015`), chat agents via `ChatAgent.SetGuard`
  (`agent/chat.go:75-78`, used at `agent/chat.go:164`), created per LLM config by
  `chatGuard()` (`server/intercept.go:27-29`).

### 5.2 intercept (rules, actions, approval, audit)

Package doc `intercept/intercept.go:1-13`: rules are DB-loaded, cached in memory, evaluated in
priority order (highest first) on every PreToolUse; actions `allow` / `deny` / `ask`; `ask`
creates an `intercept_pending` row, writes an activity to the conversation (or the task's activity
stream), and waits for `/api/intercept/pending/{id}/decide`; timeout behavior configurable at
runtime.

- Rule model: `intercept_rules` (`db/schema.sql:1033-1051`) — `name`, `enabled`, `priority`,
  `match_target` CHECK `tool_name|tool_input`, `match_type` CHECK `string|regex`, `pattern`,
  `action` CHECK `allow|deny|ask`, `message`, `timeout_enabled`, `timeout_seconds`,
  `timeout_action`.
- Matching: `Match` + `ruleMatches` (`intercept/intercept.go:508-548`); compiled regex cached
  (`compiledRule`, `:80-84`); tool allowlist `InterceptToolEnabled`
  (`IsToolEnabled`, `:233-252`).
- Decision carries rule + timeout + model provenance: `Decision`
  (`intercept/intercept.go:285-301`).
- Approval flow: `HandleAsk` (`:584-666`) inserts pending, registers a channel, re-reads to avoid a
  lost decide race, emits an `intercept_request` activity, then waits on channel/timeout/ctx;
  `Decide` (`:671-688`) resolves and wakes the channel. Pending manager `:86-119`.
- LLM fallback judge: settings keys and defaults at `intercept/intercept.go:314-336`
  (`llm_judge_enabled` default false, timeout 15 s, fail action `allow`, ask timeout 300 s, ask
  timeout action `deny`); wired by `wireInterceptReviewer` (`server/intercept.go:31-62`), which
  tags the call as the `judge` usage lane (`server/intercept.go:23,51`).
- Execution audit: `intercept_pending.audit` JSONB + `decision_source`
  (`db/schema.sql:1073-1076`); `InterceptAudit` + `CompleteIntercept`
  (`db/intercept_detail.go:19-113`); trace/correlation in `intercept/trace.go` (run id, tool-use
  id, input digest, prompt context, output capture; `contextLimit/entryLimit/promptLimit/
  outputLimit` at `intercept/trace.go:17-22`).
- Built-in rules are DB rows seeded **once**, gated by settings flags so user edits survive:
  `seedDefaultInterceptRules` (v1, `db/db.go:348-534`; ~20 rules: rm -rf, mkfs, dd, fork bomb,
  shutdown, DROP/TRUNCATE, Redis FLUSHALL, HTTP DELETE in 3 shapes, destructive paths),
  v2 (`db/db.go:536-583`; migrates the two formerly hard-coded guard patterns, exfil rule ships
  **disabled**), v3 (`db/db.go:585-617`; delete-endpoint path regex). Flags:
  `intercept_default_rules_v1/v2/v3` (`db/db.go:349,543,602`).
- Rules API/UI: `GET/POST /api/intercept/rules`, `PUT/DELETE /api/intercept/rules/{id}`,
  `POST /api/intercept/rules/{id}/toggle`, pending/history/execution endpoints,
  `GET/PUT /api/intercept/tool-config`, `GET/PUT /api/intercept/judge`,
  `GET /api/intercept/judge/usage` (`server/server.go:909-933`); UI pages
  `web/src/app/(main)/system/intercept/page.tsx`,
  `.../system/intercept/approvals/page.tsx`.
- Per-task rules: `task_intercept_rules` (`db/schema.sql:1267-1302`) with `action=block|allow`
  (`server/task_intercept.go:1-20`), i.e. a task can carry an allow-list.

### 5.3 What already enforces "authorization scope" (and what is missing)

Two mechanisms exist, neither hooked into the tool-call gate:

1. **Asset gate** (block-list + optional allow-list), applied to *assets*, not to commands:
   `EvaluateAssetGate` — block rules first, then, if any allow rule is enabled, require a match,
   else deny with "不在任务允许(白名单)范围内" (`db/asset_intercept_match.go:172-194`).
   `CheckAssetsIntercept` unions global + task-level block rules and task-level allow rules
   (`db/asset_intercept_match.go:217-250`). Enforcement points are only
   `insert_assets` (`agent/tools_insert.go:222-252`) and `add_intent`
   (`agent/tools.go:1054`). Global blocklist rules are seeded for `.gov/.gov.cn/.edu/.edu.cn`
   (`db/db.go:292-315`).
2. **Task test scope** (`task_scope`, `db/schema.sql:738-765`) used for coverage accounting and
   for filtering `list_assets` / `list_untested_assets` — not for blocking egress.

Consequently a `Bash: curl http://out-of-scope` call is **not** stopped by scope today; only the
regex-based DB rules stop specific destructive classes. The plug-in point for a scope/authorization
enforcement layer is therefore `Guard.applyIntercept` **before** rule matching, because it is the
only place every tool call traverses, it already has the task identity available via ctx
(`intercept.WithTaskContext`, `server/engine.go:1006`), and it can reuse
`CheckAssetsIntercept`/`EvaluateAssetGate` if you first extract the target host from the tool
input. Concrete steps in §10(d).

---

## 6. Traffic / proxy / evidence (browser, CDP and PoC relevance)

### 6.1 Recording proxy

`traffic` is an embedded `go-mitmproxy` addon that records every target HTTP exchange to a
human-browsable file tree plus a sidecar SQLite index (`traffic/traffic.go:1-5`). Startup:
`traffic.Open(filepath.Join(dir,"traffic"), proxyAddr)` (`server/manager.go:378`), `Start()` on a
goroutine (`server/manager.go:396-410`). Schema: `exchanges`, `exchange_bodies`, blob refs, FTS5
table `ex_fts` (`traffic/traffic.go:40-100`). Body spill/sanitize/binary tagging:
`traffic/traffic.go:515-700`. Search/pagination: `Page` (`:859`), `Get` (`:950`), `Hosts`
(`:999`), `DeleteHost/DeleteAll` (`:1030,1083`).

Agent-facing traffic tools are built in `Traffic.Tools()` (`traffic/traffic.go:2000-2120`):
`traffic_search` (light index only), `traffic_get` (full request/response), `traffic_blob`. They
are seeded into `tools` with default binding `worker` (`server/assembly.go:228-237`,
`traffic.SeedToolMetas()` at `traffic/traffic.go:2120-2123`) and injected only while capture is on
(`Manager.HostTools`, `server/manager.go:729-734`; toggle `SetTrafficEnabled`,
`server/manager.go:459-474`).

Egress plumbing that a browser/CDP workflow will inherit: agents' Bash env is `proxyEnv(addr, ca)`
setting `HTTP(S)_PROXY`, `ALL_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
`GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS` (`agent/worker.go:204-250`); WebFetch goes through the same
proxy with the MITM CA trusted (`agent/worker.go:439`, `agent/chat.go:135`). Browser MCP
proxy/CA injection: `server/manager.go:635-690`. Upstream/global proxy:
`server/manager.go:748-802`.

**CDP relevance:** there is no CDP client in-repo today; the only browser surface is the seeded
Playwright MCP (§3.5) plus the `api-recon` skill, which drives a hook/stub preload to make SPAs
render without a backend (`skills/api-recon/SKILL.md:20-40`,
`skills/api-recon/scripts/preload.js`). A CDP server would slot in exactly as an MCP server
(stdio `npx chrome-devtools-mcp` or an http/sse endpoint) and inherit the proxy/CA machinery via a
`sync…` reconciler modelled on `syncBrowserMCPProxy`, so its traffic lands in the same SQLite
index and can be bound to findings.

### 6.2 Evidence

`evidence.Store` (`evidence/store.go:23-31`) snapshots traffic into content-addressed blobs
(`<dir>/blobs/<xx>/<sha256>.bin`, `evidence/store.go:33-41`), verifies hash+length before serving
(`:43-60`), and records/binds snapshots to findings: `Record` (`:182`), `Bind` (`:197`),
`WithBinding` (`:215`), `OpenBody` (`:247`), `CopySnapshots`/`InstallSnapshots` (`:267,310`),
GC (`:406-430`). Tables: `traffic_evidence_snapshots` (`db/schema.sql:1146-1162`) and
`finding_traffic_bindings` (`db/schema.sql:1163-1177`; ordered `position`, `role`,
`UNIQUE(finding_id,snapshot_id)`).

Server-side tools: `get_finding_traffic` (`server/finding_traffic.go:368-369`),
`bind_finding_traffic` (`server/finding_workflow.go:145-146`); they are listed in
`orchestrationTools()` (`server/orchestration.go:72-88`) and seeded with agent bindings
(`server/assembly.go:212-224`, `server/finding_workflow.go:88-105`). HTTP routes are registered in
`registerFindingTraffic` (`server/finding_traffic.go:82-90`) and mounted at `server/server.go:761`;
the frontend client hits `/api/exploration/findings/{id}/traffic...`
(`web/src/lib/api.ts:598-648`). Report generation consumes the same data
(`ReporterDefaultPrompt`, `agent/promptcatalog.go:76+`).

### 6.3 Approval-time execution capture

An approved `ask` call is correlated to its actual execution and its real output:
`intercept.BindResult`/`bindResult` (`intercept/trace.go:182-190`) → `db.CompleteIntercept`
(`db/intercept_detail.go:99+`), exposed at `GET /api/intercept/history/{id}/execution`
(`server/server.go:927`). UI: `web/src/components/approval-execution-focus.tsx`.

---

## 7. Storage

### 7.1 Engine and migration strategy

PostgreSQL only (pgx driver, `go.mod:9`). DSN precedence `ARTEX_PG_DSN` env > `config.json
database` (`config/config.go:137-149`, helper `db.DSN()` at `db/db.go:92`). The DB is created on
first boot if missing (`ensureDatabase`, `db/db.go:102-130`).

`schema.sql` is `//go:embed`-ed (`db/db.go:19-21`, file `db/schema.sql`, 1386 lines, 49
`CREATE TABLE`s) and **re-executed in full on every startup** under a `pg_advisory_lock`
(`withSchemaMigrationLock`, `db/db.go:62-90`, key `7337741001` at `db/db.go:23`), with deadlock
retry (`applySchemaWithRetry`, `db/db.go:46-62`), then built-in seeding
(`db/db.go:157-171`).

**There is no versioned migration framework.** The convention is: `CREATE TABLE IF NOT EXISTS`
with the current shape, followed by idempotent
`ALTER TABLE … ADD COLUMN IF NOT EXISTS` / `DROP CONSTRAINT IF EXISTS` + re-add
(e.g. `db/schema.sql:792-794` for agents, `:848-852` for MCP, `:542-566` for tasks). Data
migrations are Go functions gated by a `settings` flag so they run once and never resurrect user
edits (`seedDefaultInterceptRulesV2/V3`, `seedAutoDefaultBindings`, `reseedWorkerPrompt`, … at
`server/orchestration.go:489-508`). New columns must therefore be added **both** to the `CREATE`
block and as an `ALTER` line.

### 7.2 Main tables (all in `db/schema.sql`)

| area | tables (line) |
|---|---|
| assets | `companies` (27), `assets` (40), `company_scope` (115) |
| exploration graph | `explorations` (153), `exploration_nodes` (170), `exploration_edges` (248), `exploration_anchors` (276), `task_constraints` (287), `activity` (298) |
| tasks | `tasks` (505), `task_categories` (493), `task_archives` (571), `task_templates` (613), `task_relations` (636), `task_asset_links` (648), `task_llm_profiles` (696), `task_scope` (738) |
| agents/prompts | `agents` (766), `agent_prompts` (804), `agent_prompt_vars` (820) |
| MCP | `mcp_servers` (833), `mcp_tools_cache` (864) |
| visibility | `agent_visibility` (877), `agent_skill_visibility` (888) |
| ledgers | `skill_usage` (900), `tool_usage` (919) |
| tools | `tools` (935) |
| chat | `conversations` (954), `conversation_activities` (970), `main_sessions` (346) |
| scheduling | `agent_triggers` (993), `scheduler_state` (1025) |
| safety | `intercept_rules` (1033), `intercept_pending` (1053), `asset_intercept_rules` (1241), `task_intercept_rules` (1267) |
| findings | `findings` (1081), `finding_retests` (1112), `traffic_evidence_snapshots` (1146), `finding_traffic_bindings` (1163) |
| ops | `settings` (356), `llm_profiles` (362), `llm_profile_health` (479), `server_logs` (1179), `notification_*` (1303,1341,1359) |

Where records live: task = `tasks` + `exploration_nodes` (the graph is the task's knowledge);
finding = `findings` (+ graph node via `findings.node_id`) + `traffic_evidence_snapshots` /
`finding_traffic_bindings` for evidence; asset = `assets` (+ `companies`, `company_scope`,
`task_scope`); tool record = `tools` (definition/binding) + `tool_usage` (call ledger); prompt =
`agent_prompts` (versions) + `agents.current_prompt_id`; traffic = filesystem (file tree + blob
spill) + SQLite sidecar index under `<data>/traffic/`; evidence = filesystem blobs + PG rows.

---

## 8. Frontend surface

### 8.1 Stack and shape

Next.js 16 App Router, React 19, shadcn/radix UI, Tailwind, Biome. `web/package.json:2-20`.
Static export for embedding: `next.config.mjs` sets `output: "export"`, `images.unoptimized`,
`trailingSlash: true` when `NEXT_EXPORT=1`; otherwise dev rewrites `/api/:path*` to
`http://localhost:8787` (`web/next.config.mjs:5-42`). Everything renders client-side
(`"use client"` on pages; the main layout does a client auth gate because middleware is unavailable
in static export — `web/src/app/(main)/layout.tsx:1-50`).

Pages (`find web/src/app -name page.tsx`):

```
(auth)/login, (auth)/setup
(external)/                        (landing)
(main)/dashboard
(main)/chat
(main)/function/tasks              (+ /tasks/detail)
(main)/function/findings           (+ /findings/detail)
(main)/function/assets
(main)/function/traffic
(main)/function/commands
(main)/function/llm-records
(main)/function/sync               (ScopeSentry asset sync)
(main)/function/workspace
(main)/system/agents               (+ /agents/detail)
(main)/system/llm
(main)/system/mcp
(main)/system/skills
(main)/system/tools
(main)/system/notify
(main)/system/intercept            (+ /intercept/approvals, /intercept/assets)
(main)/system/logs
(main)/system/settings
```

Shared pieces: `web/src/lib/api.ts` (single typed client, ~1.3k lines, wraps `fetch` and mirrors
Go handlers), `web/src/lib/types.ts` (DTOs), `web/src/components/*` (feature panels incl.
`traffic-evidence-viewer.tsx`, `transcript.tsx`, `approval-records.tsx`,
`asset-intercept-rules-editor.tsx`), `web/src/components/ui/*` (design system).

### 8.2 How a new page/route is added

App Router directories + one nav entry + API client methods. Concretely, to add
`/function/<name>`:

1. `web/src/app/(main)/function/<name>/page.tsx` — `"use client"`, default-export component,
   uses `@/components/ui/*` and `api` from `@/lib/api` (model on
   `web/src/app/(main)/system/mcp/page.tsx:1-56` or
   `web/src/app/(main)/function/traffic/page.tsx:1-120`).
2. `web/src/navigation/sidebar/sidebar-items.ts` — add `{id,title,url,icon}` to the
   `功能`(id 1) or `系统`(id 2) group (`web/src/navigation/sidebar/sidebar-items.ts:62-98`).
3. `web/src/lib/api.ts` + `web/src/lib/types.ts` — add client method(s)/DTO(s) for the new Go
   endpoints (pattern at `web/src/lib/api.ts:598-648`).
4. Go side: register routes in `server/server.go:655-933` (Go 1.22 `mux.HandleFunc("GET /path")`
   pattern; `{id}`/`{file...}` wildcards are used).
5. Serve: rebuild `cd web && npm run build:static` → `web/out`, copy to `server/webui/dist`,
   `go build -tags embedui ./cmd/artex` (`server/webui_embed.go:1-30`,
   `server/webui_stub.go:1-18`, `build.sh:123,219`). Without `-tags embedui` the binary returns
   `前端未内嵌...` 404 for non-API paths (`server/webui_stub.go:16-18`).

No codegen, no route manifest: the file tree *is* the router, and nav is a hand-written array.

---

## 9. Build / test / versions

- Go: `go 1.26.3` (`go.mod:3`); CI uses `go-version: "1.26"`
  (`.github/workflows/release.yml:45`). Verified locally: `go build ./...` exits 0, and
  `GOPROXY=off go build ./cmd/artex` also exits 0 — **no network needed** because the module cache
  在 Go module cache 中 is fully populated. There is **no `vendor/` directory**, so a
  hermetic offline build depends on that cache; `go mod vendor` is the portable option for a fork.
  `go env GOPROXY = https://goproxy.cn,direct`.
- Entry point: `cmd/artex/main.go:49` (`func main`); version injected via `-ldflags -X
  main.version` (`build.sh:219-222`).
- Release build: `./build.sh` → optionally `npm run build:static` (`build.sh:123`) → copy
  `web/out` → `server/webui/dist` → `CGO_ENABLED=0 go build -tags embedui -trimpath -ldflags
  "-s -w" -o <out> ./cmd/artex` (`build.sh:216-224`). 5 targets in CI (linux/darwin amd64+arm64,
  windows amd64) (`.github/workflows/release.yml:34-40`). Also `Dockerfile` / `Dockerfile.local` /
  `docker-compose*.yml` / `install.sh` / `update.sh`.
- Tests: 153 `*_test.go` files co-located with sources (no separate test tree); table-driven Go
  `testing`, no testify. Heavy use of `t.TempDir()`; DB-backed tests require PostgreSQL and
  **skip themselves** when no DSN is available — `db/testmain_test.go:11-32`,
  `server/testmain_test.go:1-30`, `agent/testmain_test.go:1-29` (each grabs
  `pg_advisory_lock(7337741002)` so packages serialize on a shared dev DB). Run:
  `go test ./...` (with `ARTEX_PG_DSN` set for the DB-backed subset), `go vet ./...`.
- Frontend: node_modules is **absent** in this checkout (must `npm ci`); `node v26.5.0`,
  `npm 11.17.0`, `pnpm 10.30.2` are installed. `npm run build` / `npm run build:static` /
  `npm run lint` (biome) (`web/package.json:5-11`). Only two JS tests exist:
  `web/src/lib/chat-mentions.test.mjs`, `web/src/lib/activity-merge.test.mjs`.
- Config: `config.json` (database + skill_dir) or env (`ARTEX_PG_DSN`, `ARTEX_SKILL_DIR`,
  `ARTEX_CONFIG`); `.env.example`, `config.example.json`.

---

## 10. Extension checklist

Ordered, file-by-file. Each step is the minimum needed for the goal; "verify" means an
existing test or endpoint that will catch a regression.

### (a) Add a new agent type: `researcher` / `binanalyst` (chat/trigger-driven specialists)

Recommended shape: assistant agents (like `pentest`/`reporter`), not new orchestration roles,
because the task loop is hardcoded around four roles (`server/task_llm.go:552-582`).

1. `db/db.go` — append two `builtinAgent{...}` entries to `builtinAgents` (`db/db.go:191-214`):
   `key` (`researcher`, `binanalyst`), display name, `role` = `"assistant"`, description, `vars`
   (only vars your prompt template actually uses — catalog entries are inserted per agent at
   `db/db.go:228-240`), `interactiveShell` (true for binanalyst if IDA/GDB REPLs are expected),
   `runSeconds` (`intp(0)` = unlimited, like `pentest`). The `INSERT … ON CONFLICT DO UPDATE`
   at `db/db.go:217-226` makes this idempotent on upgrade.
2. `agent/promptcatalog.go` — add `researcherDefaultTmpl` / `binanalystDefaultTmpl` consts
   (model the structure on `pentestDefaultTmpl`, `agent/promptcatalog.go:31-68`), then
   register them in `BuiltinPromptSeeds()` (`agent/promptcatalog.go:113-121`). Do **not** rely on
   `DefaultAssistantPrompt` unless you want the generic body.
3. `agent/toolcatalog.go` — add a `builtinToolsByAgent()` entry per new key
   (`agent/toolcatalog.go:34-53`) listing the domain tools they should own by default, and add the
   key to the `order` slice in `BuiltinToolSeeds()` (`agent/toolcatalog.go:65`) so the union is
   stable. If the agent is task-less (chat), the tools must tolerate a nil store — use
   `readExpTool`/`writeExpTool` (`agent/tools.go:310-330`) or a server-level tool from
   `server/orchestration.go`/`server/platform_tools.go`.
4. New domain tool groups the agents need (e.g. binary analysis) — see (b) first, then bind them
   here.
5. `server/assembly.go` — no change needed for visibility; `wireAgentAugment`
   (`server/assembly.go:25`) is key-agnostic and will pick the new rows up via
   `pg.GetAgentByKey`/`AgentSkillNames`/`AgentVisible`. If the agent must run in a **dedicated
   working dir** or get **task context**, that is code: chat agents get
   `<workDir>/sessions/<sessionID>` (`agent/chat.go:114-116`) — either accept that, or introduce
   an assistant-runtime variant.
6. Optional trigger wiring (fire the new agent on events): `agent_triggers` rows via
   `POST /api/agents/{key}/triggers` (`server/server.go:847-850`), fired by the scheduler
   (`server/scheduler.go:146,178,211,244,275,320`) → `StartTriggeredRun`
   (`server/conversations.go:610`). Model on `seedReporterAgent`
   (`server/orchestration.go:735-780`) if it must be auto-created for existing DBs (gate with a
   `settings` flag, add to the call list in `seedOrchestrationTools`,
   `server/orchestration.go:489-508`).
7. Optional skill defaults: `builtinSkillVisibility` (`db/db.go:317-330`) for shipped skills.
8. Frontend: nothing required if the agent shows up via `GET /api/agents` (the Agent page already
   lists all rows). Add a sidebar/route only if the agent needs a dedicated workspace.
9. Verify: `go build ./...`; `go test ./db ./server` (agent seeding tests:
   `db/db_test.go:74-90` asserts every `builtinAgents` key exists); restart once and check
   `GET /api/agents` + `GET /api/tools` shows the new bindings; `POST /api/conversations` with
   `agent_key=researcher` then send a message.

### (b) Add a new built-in tool group (e.g. `BinAnalysisTools`, `SourceAuditTools`)

1. `agent/tools_<domain>.go` (new file) — `func (t *ToolSet) <Domain>Tools() []actool.CoreTool`
   returning tools built with `readTool`/`writeTool` (`agent/tools.go:280-308`) or
   `readExpTool`/`writeExpTool` if they need the exploration store. Follow the local conventions:
   JSON-schema helpers `obj/str/intp` (`agent/tools.go:265-279`); return
   `actool.Errorf("…未启用…")` when a store is nil; marshal results with `jsonResult`
   (`agent/tools.go:331-339`). Never panic — handlers run on the harness goroutine
   (`agent/assembly.go:75-87` guards panics, but returning an error is the contract).
2. `agent/toolcatalog.go` — include the new group in `builtinToolsByAgent()` for each owning agent
   (`agent/toolcatalog.go:34-53`). This is what makes the tools appear in the `tools` table with
   `description`/`schema`/`agents` defaults (seed at `server/assembly.go:212-224` with
   `ON CONFLICT DO NOTHING`, `db/tools.go:31`). A tool omitted here has **no DB row** ⇒ always
   available, never bindable/filterable (fine only for SDK-level tools).
3. Wire the group into each runtime's base list, or it will never be assembled:
   - worker: `agent/worker.go:376-379`
   - planner: `agent/planner.go:375-379` (base comes from `tsx.PlannerTools()`)
   - mainagent: `agent/mainagent.go:127`
   - chat/auto/pentest/custom: `agent/chat.go:121` — because chat uses only
     `DefaultTools`, the *only* path for them is `AllDomainTools()` →
     `buildDomainReg` (`agent/tools_insert.go:688-699`, `server/assembly.go:346-360`) plus DB
     binding; make sure the new group is reachable from `MainAgentTools`/`PlannerTools`/
     `WorkerTools` so the union picks it up.
4. If the tool needs a shared/global (not per-task) instance, add a constructor in
   `server/` and expose it through `hostTools()` (`server/orchestration.go:40-66`), seeding it
   with `SeedTool` (`db/tools.go:31`) and a default binding (pattern:
   `server/assembly.go:228-237` for traffic, `server/platform_tools.go:20-37` for platform tools).
   Host tools with `deferred=true` are routed via `SearchExtraTools`/`ExecuteExtraTool`
   (`server/assembly.go:151-168`).
5. If the group belongs to a **new tool kind** (e.g. a long-running binary-analysis job),
   prefer an MCP server (§3) or a custom tool `kind` over a new CoreTool kind — custom kinds are
   only `command|script|http|shell` (`server/customtool.go:276-285`).
6. Verify: `go build ./...`; `go test ./agent ./server` (`agent/toolcatalog_test.go`,
   `server/tools_wire_test.go` assert seeding/wiring); restart → `GET /api/tools` contains the
   keys; check `GET /api/agents/{key}/visibility`-adjacent binding via
   `PUT /api/tools/{key}` (`server/server.go:858`).

### (c) Auto-wire a new MCP server type (IDA Pro / RevEng.AI / CDP) into tasks

Two levels; do 1–4 for "available", 5–7 for "automatic per task".

1. **Seed the server row** (or create it in the UI: `POST /api/mcp`, `server/server.go:867`).
   For a stdio server the row is `{name, transport:"stdio", command, args, env, enabled}` —
   pattern: the browser seed `db/db.go:255-266` (insert-if-absent, disabled by default, because
   spawning `npx` on boot is expensive). Auth/tokens go in `env` (`mcphttp` uses `env` as HTTP
   headers; stdio clients get it as process env — `server/mcpdiscover.go:31-38`).
2. **Tool cache** — nothing to do if enabled: `discoverEmptyMCPsOnStartup`
   (`server/mcpdiscover.go:69-90`, launched at `server/server.go:236`) fills `mcp_tools_cache`
   on next boot; `POST /api/mcp/{id}/refresh` forces it (`server/server.go:870`).
3. **Per-agent visibility** — insert `agent_visibility` rows (`resource_kind='mcp'`,
   `resource_id`, optional `mcp_tool_name`) via `PUT /api/agents/{key}/visibility`
   (`server/server.go:855`, handler `server/server_mgmt.go:717-737`). Directly-visible tools become
   global/unlocked at session start; skill-gated ones stay deferred (`server/assembly.go:73-145`).
4. **Prefer skill gating for heavy tool surfaces** (keeps context small and only lifts the
   toolset when relevant): create `skills/ida-analysis/SKILL.md` with
   `mcps: [ida]` in frontmatter (format `skills/api-recon/SKILL.md:1-4`; `mcps` parsed at
   `norma@v0.4.3/skill/skill.go:248-261`), assign it to agents via
   `POST /api/visibility/skill/toggle`. Then `unlockSkill` reveals `mcp__ida__*` on invocation
   (`server/assembly.go:128-145`). This ships well and needs zero Go changes.
5. **Automatic per-task injection** (the real ask): add a task↔server mapping table in
   `db/schema.sql` (e.g. `task_mcp_servers(task_id, server_id, enabled)`, written as
   `CREATE TABLE IF NOT EXISTS` **and** an `ALTER TABLE … ADD COLUMN IF NOT EXISTS` if you add
   columns later — §7.1). Add db methods beside `AgentVisible` (`db/config.go:1021-1040`).
6. **Filter at assembly time**: in `agent.ToolAugment` (`server/assembly.go:26-27`), read
   `agent.RunInfoFrom(ctx).TaskID` (`agent/runinfo.go:20-31`; note the comment at
   `server/assembly.go:140-146` already shows this ctx is available and read once per run) and
   extend `want` with the task's server ids before the `for _, m := range all` loop
   (`server/assembly.go:75-95`). The `UnlockSet`/deferred logic then needs no change: decide
   whether a task-scoped server is global or gated exactly as today
   (`server/assembly.go:115-125`).
7. **Keep the server's environment in sync with platform state** (proxy/CA/tokens/target binary):
   copy `syncBrowserMCPProxy` (`server/manager.go:635-690`) as `syncIDAMCPPaths` —
   rewrite `args`/`env` from settings each time the toggle changes, and call it from the same
   places (`server/manager.go:445,470,799`). This is how Playwright ends up recording through the
   MITM; IDA/RevEng need the same treatment for a per-task work dir (`<workDir>/tasks/<taskID>`)
   or license/token env.
8. Verify: `go build ./...`; `go test ./server` (`server/assembly_test.go`,
   `mcphttp/client_sse_test.go`); start with a stub stdio server (any MCP that answers
   `initialize`/`tools/list`) and confirm the names appear as `mcp__<server>__<tool>` in the
   session's tool list, and (if gated) only after the skill is invoked.

### (d) Add a scope/authorization enforcement hook in guard

Goal: deny (or ask) when a tool call targets something outside the task's authorized scope,
before/alongside the existing DB rules. Do **not** put this inside `applyIntercept`'s rule
matching — add it as an explicit pre-step so it can be toggled, audited and unit-tested
separately.

1. `db/schema.sql` — if a per-task allow-list is not enough, add a scope table (the existing
   `task_scope` at `db/schema.sql:738-765` plus `task_intercept_rules` with `action='allow'` at
   `:1267-1302` already model "allowed domains/IPs/CIDR" and are reusable; the missing piece is
   *default-deny when a scope exists*). Reuse `EvaluateAssetGate`
   (`db/asset_intercept_match.go:172-194`) rather than writing new matching.
2. `intercept/` (new file `scope.go`) — a `ScopeChecker` with
   `Check(ctx, toolName string, input json.RawMessage) (targets []string, err error)`:
   parse the call into target candidates. Parse from the same inputs the guard already special-cases
   (`guard/guard.go:62-76`): Bash/`shell_open` `command`, `shell_send` text; plus URL-bearing tool
   args for future CDP/browser tools. Keep the parser conservative: extract only hosts/URLs you can
   prove, and declare "cannot determine target" as a distinct outcome so policy can decide.
3. `guard/guard.go` — insert the scope step at the top of `applyIntercept`
   (`guard/guard.go:83`), before `IsToolEnabled`/`Match`, e.g.:
   ```go
   // scopeTools = tool names whose target is parseable (Bash/shell_*, future CDP tools)
   if g.scope != nil && scopeTools[ev.ToolName] {
       if dec, denied := g.scope.Check(ctx, ev.ToolName, ev.Input); denied {
           g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, ev.ToolName, ev.Input, "denied")
           return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
       }
   }
   ```
   Add `scope *intercept.ScopeChecker` to `Guard` (`guard/guard.go:31-37`) and a
   `NewWithInterceptorAndScope` constructor next to `NewWithInterceptor`
   (`guard/guard.go:41-44`), then update the two construction sites:
   `server/intercept.go:27-29` (`chatGuard`) and `server/manager.go:849` inside
   `taskFromPG` (`server/manager.go:831-851` — it already has the task id as `pt.ID`, so it can
   build a task-scoped checker).
4. **Task identity** — it is already in ctx for task workers: `intercept.WithTaskContext(workCtx,
   t.ID, label, taskEmit)` (`server/engine.go:1006`) and
   `taskInfoFromCtx` (`intercept/intercept.go:67-72`) returns it; for chat, use the conversation
   id (`intercept.ConvIDFromContext`) only if you intentionally enforce scope there (probably not).
   Fail-closed when task id is missing **only** if you also handle chat/auto agents.
5. **Admin/audit surface** — decisions already land in `intercept_pending` with
   `decision_source` (`db/schema.sql:1073-1076`) and `AuditEntry` (`guard/guard.go:21-28`), so the
   approvals UI (`web/src/app/(main)/system/intercept/approvals/page.tsx`) shows them with no
   frontend work. Add a rule/scope editor only if you need UI-driven policy: reuse
   `web/src/components/asset-intercept-rules-editor.tsx` as the pattern.
6. **Default policy** — mirror the existing seed conventions: a `settings` flag
   (`scope_enforcement_enabled`, default off) and a dial `scope_mode = off|warn|ask|deny`, so the
   fork does not brick existing installs. Read it like `judgeConfig`
   (`intercept/intercept.go:336-380`).
7. Note the removed mechanism: `guard/guard.go:4-5` documents that the RoE authorization-scope
   layer was deleted and "a replacement may be added later" — this is that replacement, and the
   redev docs should state the new semantics explicitly (default-deny scope vs. blocklist).
8. Verify: unit-test the checker (`guard/guard_test.go` currently has only 39 lines;
   `intercept/trace_test.go` / `intercept/prompt_test.go` patterns), then integration-test that a
   `Bash: curl http://evil.example` in a task whose scope is `example.com` is blocked with the
   platform-policy framing (`systemBlockMessage`, `guard/guard.go:138-141`) and that the row
   appears at `GET /api/intercept/history` (`server/server.go:925`).

---

## Appendix A — package responsibility index

| package | responsibility | key entry points |
|---|---|---|
| `cmd/artex` | process entry, flags, HTTP server bootstrap | `cmd/artex/main.go:49` |
| `server` | HTTP API (Go 1.22 mux), task Manager/Engine, agent wiring, MCP discovery, skills FS, intercept API, scheduler, triggers, notifications, self-update | `server/server.go:143` `New`, `:655` routes; `server/manager.go:344` `NewManager`; `server/engine.go:389` `NewEngine` |
| `db` | all PostgreSQL access, schema embed/apply/seed, settings, ledgers | `db/db.go:133` `Open`; `db/schema.sql` |
| `agent` | agent runtimes (goals/planner/worker/mainagent/chat), ToolSet domain tools, prompt catalog, tool catalog, assembly hooks | `agent/assembly.go:39` `AugmentTools`; `agent/chat.go:105` |
| `guard` | PreToolUse/PostToolUse safety hooks + audit ring | `guard/guard.go:57,83` |
| `intercept` | DB-driven tool-call interception (allow/deny/ask), approval pending, LLM judge, execution trace | `intercept/intercept.go:508,584,671` |
| `traffic` | embedded mitmproxy recorder, SQLite index, agent traffic tools | `traffic/traffic.go:176,2000` |
| `evidence` | content-addressed evidence snapshots, finding bindings, GC | `evidence/store.go:182,197` |
| `mcphttp` | remote MCP clients: Streamable HTTP + legacy SSE | `mcphttp/client.go:35,99,124,258` |
| `llmrec` / `llmpool` | LLM call recording; provider pool/failover | `server/task_llm.go`, `llmpool/` |
| `enrich` | async asset auto-completion (DNS/HTTP probes) | `enrich/`, wired `server/manager.go:442` |
| `notify` | IM notification channels + delivery engine | `server/notify_api.go`, `notify/` |
| `report` / `sidequestion` / `selfupdate` | report rendering/export; side-question workspace; self-update | `report/`, `sidequestion/`, `selfupdate/` |
| `config` | `config.json` + env resolution (DB DSN, skill dir) | `config/config.go:111,137` |
| `skills/` | shipped skill directories (not Go) | `skills/*/SKILL.md` |
| `web/` | Next.js App Router frontend | `web/src/app`, `web/src/lib/api.ts`, `web/src/navigation/sidebar/sidebar-items.ts` |

## Appendix B — open seams relevant to the fork (summary)

| need | seam | cost |
|---|---|---|
| new chat/trigger agent | DB rows + prompt catalog + tool bindings (§10a) | low |
| new orchestration role | `taskAgentBundle`/`agentsForTask` + new runner + engine hooks | high |
| new built-in tool group | `agent/tools_*.go` + `builtinToolsByAgent` + base-list wiring (§10b) | low |
| new MCP server (stdio/http/sse) | `mcp_servers` row + visibility or skill `mcps:` (§10c steps 1–4) | low |
| per-task MCP/工具 injection | `RunInfoFrom(ctx).TaskID` inside `ToolAugment` + mapping table (§10c 5–6) | medium |
| scope authorization | `Guard.applyIntercept` pre-step + `EvaluateAssetGate` reuse (§10d) | medium |
| CDP capture | CDP MCP server + `syncBrowserMCPProxy`-style reconciler (§6.1) | medium |
| new domain UI page | App Router page + sidebar entry + api.ts + routes (§8.2) | low |
| agent-loop semantics changes | fork/vendor `norma` (`go.mod:6`) | high |
