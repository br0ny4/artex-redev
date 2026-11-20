"use client";

// FindingGatePanel 是 0day 准入门（vulngate）的操作面板：三条门各自的可核对记录、
// 还差什么、以及导出前的最终判定。设计原则：每一条记录都必须"能被人复算"，
// 所以表单直接暴露 claim/method/expected/observed/evidence 这些结构化字段，
// 而不是让操作员在自由文本里描述"我验证过了"。

import * as React from "react";

import { PlayIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { FindingGate, GateCounterexample, GateNoveltyCheck, GatePoc, GatePocReplay } from "@/lib/types";

const SOURCE_CLASSES = [
  { value: "cve", label: "CVE 库" },
  { value: "vendor", label: "厂商公告" },
  { value: "github", label: "代码托管" },
  { value: "advisory", label: "漏洞库/通告" },
  { value: "search", label: "搜索引擎" },
  { value: "other", label: "其它" },
];

const POC_KINDS = ["http", "command", "file", "sample"];

// ProgressRow 显示某一道门的完成度（例如 3/5 条反例）。
function ProgressRow({ label, current, min }: { label: string; current: number; min: number }) {
  const ok = current >= min;
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="flex items-center gap-2 font-mono text-xs">
        <span className={ok ? "text-emerald-600" : "text-amber-600"}>
          {current}/{min}
        </span>
        {ok ? <ShieldCheckIcon className="size-3.5 text-emerald-600" /> : null}
      </span>
    </div>
  );
}

export function FindingGatePanel({ findingId, readOnly = false }: { findingId: string; readOnly?: boolean }) {
  const [gate, setGate] = React.useState<FindingGate | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState("");
  const seq = React.useRef(0);

  const load = React.useCallback(async () => {
    const mine = ++seq.current;
    try {
      const g = await api.findingGate(findingId);
      if (mine === seq.current) {
        setGate(g);
        setError("");
      }
    } catch (e) {
      if (mine === seq.current) setError(e instanceof Error ? e.message : "加载准入状态失败");
    }
  }, [findingId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const run = React.useCallback(
    async (label: string, fn: () => Promise<unknown>) => {
      setBusy(label);
      try {
        await fn();
        await load();
      } catch (e) {
        toast.error(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy("");
      }
    },
    [load],
  );

  if (error) {
    return (
      <Alert>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }
  if (!gate) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Spinner /> 加载准入状态…
      </div>
    );
  }

  const req = gate.requirements;
  const v = gate.gate;
  const passed = v.state === "passed";

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">0day 准入判定</CardTitle>
            <CardDescription>导出报告前强制校验；未过门导出会返回 409，逐条列出缺什么。</CardDescription>
          </div>
          <Badge variant={passed ? "default" : "destructive"}>{passed ? "已过门" : "未过门"}</Badge>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
            <ProgressRow label="触发验证 · 连续复现" current={v.poc_reproductions} min={req.min_reproductions} />
            <ProgressRow
              label="反例验证 · 通过的路径"
              current={v.passed_counterexamples}
              min={req.min_counterexamples}
            />
            <ProgressRow label="撞车比对 · 检索次数" current={v.novelty_queries} min={req.min_novelty_queries} />
            <ProgressRow label="撞车比对 · 信息源类别" current={v.source_classes} min={req.min_source_classes} />
          </div>
          {v.notes?.length ? (
            <Alert>
              <AlertDescription>
                <ul className="list-disc pl-4 text-xs">
                  {v.notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}
          {v.reasons?.length ? (
            <Alert variant="destructive">
              <AlertDescription>
                <ul className="list-disc pl-4 text-xs">
                  {v.reasons.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      <PocSection
        poc={gate.poc}
        replays={gate.poc_replays ?? []}
        readOnly={readOnly}
        busy={busy === "poc"}
        replayBusy={busy === "replay"}
        onSave={(p) => run("poc", () => api.setFindingPoc(findingId, p))}
        onDelete={() => run("poc", () => api.deleteFindingPoc(findingId))}
        onReplay={() =>
          run("replay", async () => {
            const r = await api.replayFindingPoc(findingId);
            if (r.matched) {
              toast.success(`重放与预期一致：HTTP ${r.replay.status_code}`);
            } else {
              toast.error(`重放与预期不一致：${(r.mismatches ?? []).join("；") || "未取到判定原因"}`);
            }
          })
        }
      />

      <CounterexampleSection
        items={gate.counterexamples ?? []}
        readOnly={readOnly}
        busy={busy === "ce"}
        onAdd={(c) => run("ce", () => api.addFindingCounterexample(findingId, c))}
        onDelete={(id) => run("ce", () => api.deleteFindingCounterexample(findingId, id))}
      />

      <NoveltySection
        items={gate.novelty_checks ?? []}
        readOnly={readOnly}
        busy={busy === "nv"}
        probeBusy={busy === "probe"}
        onAdd={(n) => run("nv", () => api.addFindingNoveltyCheck(findingId, n))}
        onDelete={(id) => run("nv", () => api.deleteFindingNoveltyCheck(findingId, id))}
        onProbe={(queries) =>
          run("probe", async () => {
            const r = await api.probeFindingNovelty(findingId, queries);
            const hits = (r.checks ?? []).reduce((n, c) => n + (c.hits?.length ?? 0), 0);
            const failed = r.errors?.length ?? 0;
            if (hits > 0) {
              toast.warning(`平台代检完成：${r.checks.length} 条记录、命中 ${hits} 条公开条目，请逐条复核是否同一漏洞`);
            } else if (failed > 0) {
              toast.warning(`平台代检部分失败（${failed} 个源）：已记录成功的检索结果，失败的不算"没撞车"`);
            } else {
              toast.success(`平台代检完成：${r.checks.length} 条记录，未命中公开条目`);
            }
          })
        }
      />
    </div>
  );
}

function PocSection({
  poc,
  replays,
  readOnly,
  busy,
  replayBusy,
  onSave,
  onDelete,
  onReplay,
}: {
  poc: GatePoc | null;
  replays: GatePocReplay[];
  readOnly: boolean;
  busy: boolean;
  replayBusy: boolean;
  onSave: (p: GatePoc) => void;
  onDelete: () => void;
  onReplay: () => void;
}) {
  const [form, setForm] = React.useState<GatePoc>({
    kind: "http",
    input: "",
    expected: "",
    observed: "",
    reproduced: 0,
    evidence: "",
    expect_status: 0,
    expect_body_contains: [],
  });
  // 预期响应片段用逗号分隔的文本框（提交时再拆成数组），避免为数组做子表单。
  const [bodyHints, setBodyHints] = React.useState("");
  React.useEffect(() => {
    if (!poc) return;
    setForm(poc);
    setBodyHints((poc.expect_body_contains ?? []).join(", "));
  }, [poc]);

  const set = <K extends keyof GatePoc>(k: K, val: GatePoc[K]) => setForm((f) => ({ ...f, [k]: val }));
  const submit = () =>
    onSave({
      ...form,
      expect_body_contains: bodyHints
        .split(/[,，\s]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    });
  const canReplay = Boolean(poc) && poc?.kind === "http" && !readOnly;
  const expectReady = (poc?.expect_status ?? 0) > 0;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle className="text-sm">门三 · 触发验证（PoC）</CardTitle>
          <CardDescription>
            无 PoC 不算 finding：写清怎么触发、看到了什么、连续复现几次。给出可机器判定的预期后可让平台代跑重放。
          </CardDescription>
        </div>
        {poc && !readOnly ? (
          <Button variant="ghost" size="sm" onClick={onDelete} disabled={busy}>
            <Trash2Icon className="size-3.5" />
          </Button>
        ) : null}
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="flex flex-col gap-1.5">
            <Label>触发方式</Label>
            <div className="flex flex-wrap gap-1.5">
              {POC_KINDS.map((k) => (
                <Button
                  key={k}
                  size="sm"
                  variant={form.kind === k ? "default" : "outline"}
                  disabled={readOnly}
                  onClick={() => set("kind", k)}
                >
                  {k}
                </Button>
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>连续复现次数</Label>
            <Input
              type="number"
              min={0}
              value={form.reproduced}
              disabled={readOnly}
              onChange={(e) => set("reproduced", Number(e.target.value) || 0)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>凭据（流量 id / 输出摘要）</Label>
            <Input value={form.evidence} disabled={readOnly} onChange={(e) => set("evidence", e.target.value)} />
          </div>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label>复现步骤（可复制粘贴的 HTTP 请求或命令）</Label>
            <Textarea
              rows={4}
              className="font-mono text-xs"
              value={form.input}
              disabled={readOnly}
              onChange={(e) => set("input", e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>预期结果（人读）</Label>
            <Textarea
              rows={2}
              value={form.expected}
              disabled={readOnly}
              onChange={(e) => set("expected", e.target.value)}
            />
            <Label>实际观察结果</Label>
            <Textarea
              rows={2}
              value={form.observed}
              disabled={readOnly}
              onChange={(e) => set("observed", e.target.value)}
            />
          </div>
        </div>
        <div className="grid gap-3 rounded-md border border-dashed p-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label>机器可判预期 · HTTP 状态码</Label>
            <Input
              type="number"
              min={0}
              max={599}
              placeholder="例如 200"
              value={form.expect_status ?? 0}
              disabled={readOnly}
              onChange={(e) => set("expect_status", Number(e.target.value) || 0)}
            />
            <p className="text-xs text-muted-foreground">
              填了它平台才能代跑重放并自动判定「这次是不是真的复现」；不填只能靠人工计数。
            </p>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>机器可判预期 · 响应体须包含</Label>
            <Input
              placeholder="用逗号分隔，例如 admin, user_id"
              value={bodyHints}
              disabled={readOnly}
              onChange={(e) => setBodyHints(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              大小写不敏感的包含匹配；保守一点，只写能证明漏洞存在的最短片段。
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs text-muted-foreground">
            重放走录制代理（受 L3 范围/语义/预算管控），只有 kind=http 能代跑；command/file/sample
            涉及在宿主机执行代码，平台不代跑。
          </p>
          <div className="flex items-center gap-2">
            {canReplay ? (
              <Button size="sm" variant="outline" disabled={busy || replayBusy || !expectReady} onClick={onReplay}>
                {replayBusy ? <Spinner /> : <PlayIcon className="size-3.5" />} 平台重放
              </Button>
            ) : null}
            {!readOnly ? (
              <Button size="sm" disabled={busy} onClick={submit}>
                {busy ? <Spinner /> : null} 保存 PoC
              </Button>
            ) : null}
          </div>
        </div>
        {poc && !expectReady ? (
          <p className="text-xs text-amber-600">该 PoC 还没有 expect_status：补上并保存后可点「平台重放」。</p>
        ) : null}
        {replays.length ? (
          <div className="flex flex-col gap-1.5 border-t pt-3">
            <Label>重放历史（由平台发包，机器判定）</Label>
            <ul className="flex flex-col gap-1 text-xs">
              {replays.map((r, i) => (
                <li key={r.id ?? i} className="flex flex-wrap items-center gap-2 font-mono">
                  <Badge variant={r.matched ? "default" : "destructive"}>{r.matched ? "一致" : "不一致"}</Badge>
                  <span>HTTP {r.status_code}</span>
                  {r.traffic_id ? <span className="text-muted-foreground">traffic={r.traffic_id}</span> : null}
                  <span className="text-muted-foreground">{r.detail}</span>
                  <span className="text-muted-foreground">{new Date(r.created_at).toLocaleString()}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function CounterexampleSection({
  items,
  readOnly,
  busy,
  onAdd,
  onDelete,
}: {
  items: GateCounterexample[];
  readOnly: boolean;
  busy: boolean;
  onAdd: (c: Omit<GateCounterexample, "id" | "ordinal">) => void;
  onDelete: (id: number) => void;
}) {
  const [form, setForm] = React.useState({
    claim: "",
    method: "",
    expected: "",
    observed: "",
    evidence: "",
    traffic_ids: "",
    passed: true,
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">门一 · 反例验证</CardTitle>
        <CardDescription>
          每条反例要能排除一条具体误报路径；同一手法复制多份不算数（服务端按 method+claim 去重）。
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {items.length === 0 ? <p className="text-sm text-muted-foreground">（还没有记录）</p> : null}
        <div className="flex flex-col divide-y rounded-md border">
          {items.map((c) => (
            <div key={c.id ?? c.ordinal} className="flex items-start gap-3 p-2.5">
              <Badge variant={c.passed ? "default" : "destructive"} className="mt-0.5 shrink-0">
                {c.passed ? "通过" : "未通过"}
              </Badge>
              <div className="flex min-w-0 flex-1 flex-col gap-0.5 text-xs">
                <span className="font-medium">{c.claim}</span>
                <span className="text-muted-foreground">
                  手法：{c.method} · 预期：{c.expected} · 实际：{c.observed}
                </span>
                {c.evidence ? <code className="truncate text-muted-foreground">{c.evidence}</code> : null}
              </div>
              {!readOnly && c.id ? (
                <Button variant="ghost" size="sm" disabled={busy} onClick={() => onDelete(c.id as number)}>
                  <Trash2Icon className="size-3.5" />
                </Button>
              ) : null}
            </div>
          ))}
        </div>
        {!readOnly ? (
          <div className="flex flex-col gap-2 rounded-md border p-2.5">
            <div className="grid gap-2 sm:grid-cols-2">
              <Input
                placeholder="要排除的误报路径（claim）"
                value={form.claim}
                onChange={(e) => setForm({ ...form, claim: e.target.value })}
              />
              <Input
                placeholder="验证手法（method）"
                value={form.method}
                onChange={(e) => setForm({ ...form, method: e.target.value })}
              />
              <Input
                placeholder="正常应观察到什么（expected）"
                value={form.expected}
                onChange={(e) => setForm({ ...form, expected: e.target.value })}
              />
              <Input
                placeholder="实际观察到什么（observed）"
                value={form.observed}
                onChange={(e) => setForm({ ...form, observed: e.target.value })}
              />
              <Input
                placeholder="凭据：流量 id / 命令输出"
                value={form.evidence}
                onChange={(e) => setForm({ ...form, evidence: e.target.value })}
              />
              <Input
                placeholder="引用的真实流量 id，逗号分隔（可选）"
                value={form.traffic_ids}
                onChange={(e) => setForm({ ...form, traffic_ids: e.target.value })}
              />
              <span className="flex items-center gap-2 text-sm">
                <Checkbox
                  id="ce-passed"
                  checked={form.passed}
                  onCheckedChange={(checked) => setForm({ ...form, passed: checked === true })}
                />
                <label htmlFor="ce-passed">漏洞在该反例条件下未出现</label>
              </span>
            </div>
            <div className="flex justify-end">
              <Button
                size="sm"
                disabled={busy}
                onClick={() => {
                  onAdd({
                    claim: form.claim,
                    method: form.method,
                    expected: form.expected,
                    observed: form.observed,
                    evidence: form.evidence,
                    passed: form.passed,
                    traffic_ids: form.traffic_ids
                      .split(/[,，\s]+/)
                      .map((v: string) => v.trim())
                      .filter(Boolean),
                  });
                  setForm({
                    claim: "",
                    method: "",
                    expected: "",
                    observed: "",
                    evidence: "",
                    traffic_ids: "",
                    passed: true,
                  });
                }}
              >
                {busy ? <Spinner /> : null} 添加反例
              </Button>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

function NoveltySection({
  items,
  readOnly,
  busy,
  probeBusy,
  onAdd,
  onDelete,
  onProbe,
}: {
  items: GateNoveltyCheck[];
  readOnly: boolean;
  busy: boolean;
  probeBusy: boolean;
  onAdd: (n: { query: string; source_class: string; hits: string[]; same_vuln: boolean }) => void;
  onDelete: (id: number) => void;
  onProbe: (queries: string[]) => void;
}) {
  const [form, setForm] = React.useState({ query: "", source_class: "cve", hits: "", same_vuln: false });
  const [probe, setProbe] = React.useState("");
  const probeQueries = probe
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">门二 · 撞车比对</CardTitle>
        <CardDescription>
          至少 3 次不同检索、覆盖 2 类以上信息源；命中已公开的同一致命漏洞会被直接阻断。
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {items.length === 0 ? <p className="text-sm text-muted-foreground">（还没有记录）</p> : null}
        <div className="flex flex-col divide-y rounded-md border">
          {items.map((n) => (
            <div key={n.id} className="flex items-start gap-3 p-2.5">
              <Badge variant={n.same_vuln ? "destructive" : "outline"} className="mt-0.5 shrink-0">
                {n.same_vuln
                  ? "撞车"
                  : (SOURCE_CLASSES.find((s) => s.value === n.source_class)?.label ?? n.source_class)}
              </Badge>
              <Badge variant="secondary" className="mt-0.5 shrink-0">
                {n.origin === "platform" ? "平台代检" : "人工登记"}
              </Badge>
              <div className="flex min-w-0 flex-1 flex-col gap-0.5 text-xs">
                <span className="font-medium break-all">{n.query}</span>
                {n.hits?.length ? <span className="text-muted-foreground">命中：{n.hits.join(" / ")}</span> : null}
              </div>
              {!readOnly && n.id ? (
                <Button variant="ghost" size="sm" disabled={busy} onClick={() => onDelete(n.id as number)}>
                  <Trash2Icon className="size-3.5" />
                </Button>
              ) : null}
            </div>
          ))}
        </div>
        {!readOnly ? (
          <div className="flex flex-col gap-2 rounded-md border border-dashed p-2.5">
            <div className="flex flex-col gap-1">
              <span className="text-sm font-medium">平台代检（真实请求 NVD / CISA KEV）</span>
              <span className="text-xs text-muted-foreground">
                每行一条查询（最多 5 条），建议写"产品 + 版本 +
                漏洞特征"。平台会把命中的公开条目落库并标注「平台代检」；
                是否同一个漏洞仍要你复核后手动标记撞车。检索失败不会记成"没撞车"。
              </span>
            </div>
            <Textarea
              rows={3}
              className="font-mono text-xs"
              placeholder={"apache httpd 2.4.49 path traversal\nlog4j2 jndi rce"}
              value={probe}
              onChange={(e) => setProbe(e.target.value)}
            />
            <div className="flex justify-end">
              <Button
                size="sm"
                variant="outline"
                disabled={busy || probeBusy || probeQueries.length === 0 || probeQueries.length > 5}
                onClick={() => onProbe(probeQueries)}
              >
                {probeBusy ? <Spinner /> : <ShieldCheckIcon className="size-3.5" />} 平台代检
              </Button>
            </div>
          </div>
        ) : null}
        {!readOnly ? (
          <div className="flex flex-col gap-2 rounded-md border p-2.5">
            <div className="grid gap-2 sm:grid-cols-2">
              <Input
                placeholder="实际检索关键词（query）"
                value={form.query}
                onChange={(e) => setForm({ ...form, query: e.target.value })}
              />
              <div className="flex flex-wrap gap-1.5">
                {SOURCE_CLASSES.map((s) => (
                  <Button
                    key={s.value}
                    size="sm"
                    variant={form.source_class === s.value ? "default" : "outline"}
                    onClick={() => setForm({ ...form, source_class: s.value })}
                  >
                    {s.label}
                  </Button>
                ))}
              </div>
              <Input
                placeholder="命中标题/链接，逗号分隔（可空）"
                value={form.hits}
                onChange={(e) => setForm({ ...form, hits: e.target.value })}
              />
              <span className="flex items-center gap-2 text-sm">
                <Checkbox
                  id="nv-same-vuln"
                  checked={form.same_vuln}
                  onCheckedChange={(checked) => setForm({ ...form, same_vuln: checked === true })}
                />
                <label htmlFor="nv-same-vuln">命中的是同一漏洞</label>
              </span>
            </div>
            <div className="flex justify-end">
              <Button
                size="sm"
                disabled={busy}
                onClick={() => {
                  onAdd({
                    query: form.query,
                    source_class: form.source_class,
                    hits: form.hits
                      .split(/[,，]/)
                      .map((s) => s.trim())
                      .filter(Boolean),
                    same_vuln: form.same_vuln,
                  });
                  setForm({ query: "", source_class: "cve", hits: "", same_vuln: false });
                }}
              >
                {busy ? <Spinner /> : null} 添加检索记录
              </Button>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
