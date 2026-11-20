"use client";

// FindingGatePanel 是 0day 准入门（vulngate）的操作面板：三条门各自的可核对记录、
// 还差什么、以及导出前的最终判定。设计原则：每一条记录都必须"能被人复算"，
// 所以表单直接暴露 claim/method/expected/observed/evidence 这些结构化字段，
// 而不是让操作员在自由文本里描述"我验证过了"。

import * as React from "react";

import { ShieldCheckIcon, Trash2Icon } from "lucide-react";
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
import type { FindingGate, GateCounterexample, GateNoveltyCheck, GatePoc } from "@/lib/types";

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
        readOnly={readOnly}
        busy={busy === "poc"}
        onSave={(p) => run("poc", () => api.setFindingPoc(findingId, p))}
        onDelete={() => run("poc", () => api.deleteFindingPoc(findingId))}
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
        onAdd={(n) => run("nv", () => api.addFindingNoveltyCheck(findingId, n))}
        onDelete={(id) => run("nv", () => api.deleteFindingNoveltyCheck(findingId, id))}
      />
    </div>
  );
}

function PocSection({
  poc,
  readOnly,
  busy,
  onSave,
  onDelete,
}: {
  poc: GatePoc | null;
  readOnly: boolean;
  busy: boolean;
  onSave: (p: GatePoc) => void;
  onDelete: () => void;
}) {
  const [form, setForm] = React.useState<GatePoc>({
    kind: "http",
    input: "",
    expected: "",
    observed: "",
    reproduced: 0,
    evidence: "",
  });
  React.useEffect(() => {
    if (poc) setForm(poc);
  }, [poc]);

  const set = <K extends keyof GatePoc>(k: K, val: GatePoc[K]) => setForm((f) => ({ ...f, [k]: val }));

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle className="text-sm">门三 · 触发验证（PoC）</CardTitle>
          <CardDescription>无 PoC 不算 finding：写清怎么触发、看到了什么、连续复现几次。</CardDescription>
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
            <Label>复现步骤（可复制粘贴）</Label>
            <Textarea
              rows={4}
              className="font-mono text-xs"
              value={form.input}
              disabled={readOnly}
              onChange={(e) => set("input", e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>预期结果</Label>
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
        {!readOnly ? (
          <div className="flex justify-end">
            <Button size="sm" disabled={busy} onClick={() => onSave(form)}>
              {busy ? <Spinner /> : null} 保存 PoC
            </Button>
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
  onAdd,
  onDelete,
}: {
  items: GateNoveltyCheck[];
  readOnly: boolean;
  busy: boolean;
  onAdd: (n: { query: string; source_class: string; hits: string[]; same_vuln: boolean }) => void;
  onDelete: (id: number) => void;
}) {
  const [form, setForm] = React.useState({ query: "", source_class: "cve", hits: "", same_vuln: false });
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
