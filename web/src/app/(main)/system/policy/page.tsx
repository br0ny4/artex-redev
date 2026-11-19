"use client";

// 规范执行层（policy）操作台。
//
// 这一页承载的是"硬约束"的可观测面：授权范围/预算/语义拦截到底生效了没有、
// 平台在什么时候把测试**全量停下**等操作员答复、以及判定流水能不能自证未被篡改。
// 规范 7.3 要求"停止是全量的、不是单接口的"，所以挂起横幅优先于一切列表。
//
// 注意：这一页只做展示与答复，不提供"绕过策略"的开关——策略一旦启用就没有 UI 开关，
// 这是故意的（提示词是软约束，硬约束必须由平台工程层实现）。

import * as React from "react";

import { Loader2Icon, RefreshCwIcon, ShieldAlertIcon, ShieldCheckIcon, ShieldOffIcon, SirenIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { PolicyDecision, PolicyEngineHold, PolicyHold, PolicyStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

function fmtTime(ts?: string | null) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const actionTone: Record<string, string> = {
  deny: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30",
  hold: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30",
  warn: "bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30",
};

const sourceLabel: Record<string, string> = {
  "L1-command": "命令",
  "L3-request": "出站请求",
  "L3-response": "响应内容",
  "L5-hold": "全局挂起",
};

const reasonLabel: Record<string, string> = {
  SCOPE_UNCERTAIN: "范围归属不明",
  SEMANTICS_UNCERTAIN: "接口语义判不清",
  BUDGET_EXHAUSTED: "预算耗尽",
  WINDOW_CLOSED: "授权窗口外",
};

export default function PolicyPage() {
  const [status, setStatus] = React.useState<PolicyStatus | null>(null);
  const [holds, setHolds] = React.useState<PolicyHold[]>([]);
  const [engineHold, setEngineHold] = React.useState<PolicyEngineHold | undefined>();
  const [decisions, setDecisions] = React.useState<PolicyDecision[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [chain, setChain] = React.useState<{ ok: boolean; verified?: number; error?: string } | null>(null);
  const [answering, setAnswering] = React.useState<PolicyHold | null>(null);
  const [answerText, setAnswerText] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const [st, h, d] = await Promise.all([api.policyStatus(), api.policyHolds(), api.policyDecisions(100)]);
      setStatus(st);
      setHolds(h.holds);
      setEngineHold(h.engine_hold);
      setDecisions(d);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载规范执行状态失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 挂起状态用轮询：它是"测试是否还在跑"的唯一真相，操作员不该靠刷新页面才发现。
  React.useEffect(() => {
    if (!status?.enabled) return;
    const t = setInterval(() => {
      api
        .policyHolds()
        .then((h) => {
          setHolds(h.holds);
          setEngineHold(h.engine_hold);
        })
        .catch(() => {
          // 轮询失败静默：下一轮会重试，反复弹 toast 只会盖住挂起横幅。
        });
    }, 5000);
    return () => clearInterval(t);
  }, [status?.enabled]);

  const verifyChain = async () => {
    setBusy(true);
    try {
      setChain(await api.policyChain());
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "校验失败");
    } finally {
      setBusy(false);
    }
  };

  const submitAnswer = async (resume: boolean) => {
    if (!answering) return;
    if (resume && !answerText.trim()) {
      toast.error("要求恢复时必须写明答复内容；答复模糊时请再确认一次");
      return;
    }
    setBusy(true);
    try {
      const r = await api.answerPolicyHold(answering.id, answerText.trim(), resume);
      if (r.resume_intent && !r.resumed) {
        // 进程重启后引擎里已没有这条挂起：DB 答复记下了，但恢复需要人工确认任务状态。
        toast.warning("答复已记录；引擎中未找到该挂起（可能已随进程重启失效），请确认任务是否继续");
      } else {
        toast.success(r.resumed ? "已答复并恢复测试" : "答复已记录（测试仍停止）");
      }
      setAnswering(null);
      setAnswerText("");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "答复失败");
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4 p-6">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  // 引擎内存里的挂起是"此刻是否仍在停止"的真相；DB 记录只是它的持久化副本。
  const openHold = holds.find((h) => h.status === "open");
  const activeHold = engineHold
    ? { code: engineHold.rule, text: engineHold.reason, question: engineHold.question, since: engineHold.since }
    : openHold
      ? {
          code: openHold.reason,
          text: reasonLabel[openHold.reason] ?? openHold.reason,
          question: openHold.question,
          since: openHold.created_at,
        }
      : undefined;

  return (
    <div className="mx-auto w-full max-w-6xl space-y-5 p-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">规范执行</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            授权范围、预算、破坏性操作与语义歧义由平台工程层强制执行；判不清一律停止并等操作员答复。
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={busy}>
          <RefreshCwIcon className="mr-1.5 size-4" />
          刷新
        </Button>
      </header>

      {/* 全量停止横幅：优先于其余一切信息 */}
      {activeHold && (
        <Card className="border-red-500/40 bg-red-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-red-600 dark:text-red-400">
              <SirenIcon className="size-5" />
              测试已全量停止，等待操作员答复
            </CardTitle>
            <CardDescription>
              {activeHold.text} · 挂起于 {fmtTime(activeHold.since)}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm">{activeHold.question}</p>
            <p className="text-xs text-muted-foreground">
              规范 7.3：停止是全量的，不是单接口的。未获得明确答复前，所有请求与命令都会被挡下。
            </p>
            <div className="flex flex-wrap gap-2">
              {openHold ? (
                <Button
                  size="sm"
                  onClick={() => {
                    setAnswering(openHold);
                    setAnswerText("");
                  }}
                >
                  答复并决定是否恢复
                </Button>
              ) : (
                <span className="text-xs text-muted-foreground">
                  该挂起来自引擎内存、没有对应的待答复记录（可能正在落库）。
                </span>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            {status?.enabled ? (
              <ShieldCheckIcon className="size-4 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <ShieldOffIcon className="size-4 text-muted-foreground" />
            )}
            执行层状态
          </CardTitle>
          <CardDescription>
            {status?.enabled
              ? "策略已启用：范围/预算/语义判定在 guard 与流量代理两处强制生效，录制不可关闭。"
              : (status?.reason ?? "未启用")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {status?.enabled ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <Field label="授权 ID" value={status.engagement?.id || "—"} />
              <Field
                label="客户 / 项目"
                value={[status.engagement?.client, status.engagement?.title].filter(Boolean).join(" · ") || "—"}
              />
              <Field label="模式" value={`${status.mode ?? "—"}${status.enforcing ? "（强制执行）" : "（仅提示）"}`} />
              <Field label="规范版本" value={status.spec_version || "—"} />
              <Field
                label="授权窗口"
                value={
                  status.engagement?.window
                    ? `${status.engagement.window.starts_at ?? "?"} → ${status.engagement.window.ends_at ?? "?"}`
                    : "—"
                }
              />
              <Field label="范围内域名" value={String(status.engagement?.scope?.domains?.length ?? 0) + " 个"} />
              <Field label="握手令牌" value={status.handshake || "—"} mono />
              <Field
                label="判定记录"
                value={
                  chain
                    ? chain.ok
                      ? `链完整（${chain.verified ?? 0} 条）`
                      : `校验失败：${chain.error ?? "未知"}`
                    : "未校验"
                }
                action={
                  <Button variant="outline" size="sm" onClick={() => void verifyChain()} disabled={busy}>
                    校验审计链
                  </Button>
                }
              />
            </div>
          ) : (
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">
                未配置授权文件时，上游行为保持不变（无范围/预算/语义拦截）。接入方式：
              </p>
              <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
                {`# 1. 写授权上下文（示例见 policy/web-pentest/deployment-context.example.yaml）
export ARTEX_ENGAGEMENT_FILE=/etc/artex/engagement.yaml
# 2. 重启后端；策略启用后流量录制强制开启且不可关闭`}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>

      <Tabs defaultValue="holds">
        <TabsList>
          <TabsTrigger value="holds">
            挂起{" "}
            <Badge variant="secondary" className="ml-1.5">
              {holds.filter((h) => h.status === "open").length}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="decisions">判定流水</TabsTrigger>
        </TabsList>

        <TabsContent value="holds" className="mt-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">待答复的挂起</CardTitle>
              <CardDescription>答复后测试才会恢复；答复模糊时请选"仅记录答复"，再确认一轮。</CardDescription>
            </CardHeader>
            <CardContent>
              {holds.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">没有挂起记录</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-14">ID</TableHead>
                      <TableHead>原因</TableHead>
                      <TableHead>问题</TableHead>
                      <TableHead className="w-40">时间</TableHead>
                      <TableHead className="w-24">状态</TableHead>
                      <TableHead className="w-24" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {holds.map((h) => (
                      <TableRow key={h.id}>
                        <TableCell className="font-mono text-xs">{h.id}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="border-amber-500/40 text-amber-600 dark:text-amber-400">
                            {reasonLabel[h.reason] ?? h.reason}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-md text-sm">
                          <div className="line-clamp-3">{h.question || "—"}</div>
                          {h.answer ? (
                            <div className="mt-1 text-xs text-muted-foreground">
                              答复（{h.answered_by || "operator"}）：{h.answer}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{fmtTime(h.created_at)}</TableCell>
                        <TableCell>
                          <Badge variant={h.status === "open" ? "default" : "secondary"}>
                            {h.status === "open" ? "等待答复" : h.status === "resumed" ? "已恢复" : h.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {h.status === "open" && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => {
                                setAnswering(h);
                                setAnswerText("");
                              }}
                            >
                              答复
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="decisions" className="mt-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">最近 100 条判定</CardTitle>
              <CardDescription>
                每条都带 prev_hash/hash：改动任何一条都会让后续链失配，报告里可据此自证。
              </CardDescription>
            </CardHeader>
            <CardContent>
              {decisions.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">暂无判定记录</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-40">时间</TableHead>
                      <TableHead className="w-24">动作</TableHead>
                      <TableHead className="w-24">来源</TableHead>
                      <TableHead>目标</TableHead>
                      <TableHead>规则 / 理由</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {decisions.map((d) => (
                      <TableRow key={d.id}>
                        <TableCell className="text-xs text-muted-foreground">{fmtTime(d.ts)}</TableCell>
                        <TableCell>
                          <span
                            className={cn(
                              "inline-flex rounded border px-1.5 py-0.5 text-xs",
                              actionTone[d.action] ?? "border-border text-muted-foreground",
                            )}
                          >
                            {d.action}
                          </span>
                        </TableCell>
                        <TableCell className="text-xs">{sourceLabel[d.source] ?? d.source}</TableCell>
                        <TableCell className="max-w-xs truncate font-mono text-xs">
                          {d.host ? `${d.method || ""} ${d.host}${d.path || ""}` : d.path || "—"}
                        </TableCell>
                        <TableCell className="max-w-md text-xs">
                          <div className="font-mono">{d.rule}</div>
                          <div className="truncate text-muted-foreground">{d.reason}</div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Dialog open={!!answering} onOpenChange={(o) => !o && setAnswering(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlertIcon className="size-4 text-amber-600 dark:text-amber-400" />
              答复挂起
            </DialogTitle>
            <DialogDescription>{answering?.question}</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Textarea
              value={answerText}
              onChange={(e) => setAnswerText(e.target.value)}
              placeholder="把结论原样写清楚：该目标是否在授权范围内、该接口是否允许此操作、下一步如何处理……"
              rows={5}
            />
            <p className="text-xs text-muted-foreground">
              "已确认 / 在范围内 / 可继续"之外的模糊答复，请用"仅记录答复"，不要直接恢复。
            </p>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="ghost" onClick={() => setAnswering(null)} disabled={busy}>
              取消
            </Button>
            <Button variant="outline" onClick={() => void submitAnswer(false)} disabled={busy}>
              仅记录答复（继续保持停止）
            </Button>
            <Button onClick={() => void submitAnswer(true)} disabled={busy}>
              {busy && <Loader2Icon className="mr-1.5 size-4 animate-spin" />}
              答复并恢复
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  action,
}: {
  label: string;
  value: string;
  mono?: boolean;
  action?: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={cn("flex items-center gap-2 text-sm", mono && "font-mono text-xs")}>
        <span className="truncate">{value}</span>
        {action}
      </div>
    </div>
  );
}
