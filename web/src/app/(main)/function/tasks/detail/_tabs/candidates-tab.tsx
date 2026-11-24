"use client";

// 0day 流水线阶段 2–3：候选可疑点。这一页回答"这条结论从哪来"——
// 每跳证据由服务端核对（traffic id 是否真实存在、源码是否在授权目录清单内），
// 这里显示的 reachability 是平台算的，不是 agent 自述的。

import * as React from "react";

import { CheckCircle2Icon, RefreshCwIcon, XCircleIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { VulnCandidate, VulnCandidateHop } from "@/lib/types";

const KIND_LABEL: Record<string, string> = {
  sink: "危险操作",
  parse: "解析器",
  logic: "业务逻辑",
  auth: "认证授权",
  config: "配置",
  other: "其他",
};

const REACH: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
  verified: { label: "路径已核对", variant: "default" },
  partial: { label: "部分核对", variant: "secondary" },
  claimed: { label: "未核对", variant: "outline" },
  unknown: { label: "无路径", variant: "outline" },
};

const HOP_LABEL: Record<string, string> = { traffic: "流量", source: "源码", command: "命令", other: "其他" };

function HopRow({ hop }: { hop: VulnCandidateHop }) {
  return (
    <li className="flex flex-col gap-1 rounded-md border px-2 py-1.5 text-xs">
      <div className="flex items-center gap-2">
        <Badge variant="outline">{HOP_LABEL[hop.ref_kind] ?? hop.ref_kind}</Badge>
        <code className="truncate font-mono text-[11px]">{hop.ref}</code>
        {hop.verified ? (
          <CheckCircle2Icon className="ml-auto size-3.5 shrink-0 text-emerald-600" />
        ) : (
          <XCircleIcon className="ml-auto size-3.5 shrink-0 text-muted-foreground" />
        )}
      </div>
      {hop.claim ? <span className="text-muted-foreground">{hop.claim}</span> : null}
      {hop.verified_detail ? (
        <span className={hop.verified ? "text-emerald-700" : "text-amber-700"}>{hop.verified_detail}</span>
      ) : null}
    </li>
  );
}

function CandidateCard({ candidate, onChanged }: { candidate: VulnCandidate; onChanged: () => void }) {
  const [findingId, setFindingId] = React.useState("");
  const [busy, setBusy] = React.useState("");
  const [error, setError] = React.useState("");
  const reach = REACH[candidate.reachability] ?? REACH.unknown;

  async function act(kind: "link" | "dismiss" | "reopen") {
    setError("");
    try {
      setBusy(kind);
      if (kind === "link") {
        const id = Number.parseInt(findingId, 10);
        if (!Number.isFinite(id) || id <= 0) {
          setError("先填要关联的漏洞 id（可在「发现」页拿到）");
          return;
        }
        await api.linkVulnCandidate(candidate.id, id);
      } else {
        await api.setVulnCandidateStatus(candidate.id, kind === "dismiss" ? "dismissed" : "open");
      }
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }

  return (
    <Card>
      <CardHeader className="gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="text-sm">{candidate.title}</CardTitle>
          <Badge variant="secondary">{KIND_LABEL[candidate.kind] ?? candidate.kind}</Badge>
          <Badge variant={reach.variant}>{reach.label}</Badge>
          {candidate.status === "converted" ? (
            <Badge>已转结论 #{candidate.finding_id}</Badge>
          ) : candidate.status === "dismissed" ? (
            <Badge variant="outline">已忽略</Badge>
          ) : null}
        </div>
        <CardDescription className="font-mono text-[11px]">{candidate.location}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {candidate.rationale ? <p className="text-xs text-muted-foreground">{candidate.rationale}</p> : null}
        {candidate.hops && candidate.hops.length > 0 ? (
          <ul className="flex flex-col gap-1.5">
            {candidate.hops.map((hop) => (
              <HopRow key={hop.id ?? hop.ordinal} hop={hop} />
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">还没有登记入口→sink 路径：可达性无法确认（阶段 3）。</p>
        )}
        {error ? <p className="text-xs text-destructive">{error}</p> : null}
        <div className="flex flex-wrap items-center gap-2">
          {candidate.status !== "converted" ? (
            <>
              <Input
                className="h-8 w-32"
                inputMode="numeric"
                onChange={(e) => setFindingId(e.target.value)}
                placeholder="漏洞 id"
                value={findingId}
              />
              <Button disabled={busy !== ""} onClick={() => void act("link")} size="sm" variant="outline">
                转结论
              </Button>
            </>
          ) : null}
          {candidate.status === "dismissed" ? (
            <Button disabled={busy !== ""} onClick={() => void act("reopen")} size="sm" variant="ghost">
              恢复
            </Button>
          ) : candidate.status !== "converted" ? (
            <Button disabled={busy !== ""} onClick={() => void act("dismiss")} size="sm" variant="ghost">
              忽略
            </Button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

export function CandidatesTab({ taskId }: { taskId: string }) {
  const [items, setItems] = React.useState<VulnCandidate[] | null>(null);
  const [error, setError] = React.useState("");
  const [version, setVersion] = React.useState(0);
  const refresh = React.useCallback(() => setVersion((v) => v + 1), []);

  React.useEffect(() => {
    let disposed = false;
    async function load() {
      try {
        const list = await api.vulnCandidates(taskId);
        if (!disposed) {
          setItems(list);
          setError("");
        }
      } catch (e) {
        if (!disposed) setError((e as Error).message);
      }
    }
    void version;
    void load();
    return () => {
      disposed = true;
    };
  }, [taskId, version]);

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <CardTitle className="text-sm">候选可疑点</CardTitle>
          <CardDescription>
            Agent 登记的"值得验证的路径"。每跳证据由平台核对：流量 id 必须真实存在，源码位置必须在授权目录清单内；
            核对不通过只是降级显示，不会阻止你继续验证。验证成功后用 report_finding 带 candidate_id 转成结论。
          </CardDescription>
        </div>
        <Button onClick={refresh} size="sm" variant="outline">
          <RefreshCwIcon className="size-3.5" />
          刷新
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error ? <p className="text-xs text-destructive">{error}</p> : null}
        {items === null ? (
          <p className="text-xs text-muted-foreground">加载中…</p>
        ) : items.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>还没有候选</EmptyTitle>
              <EmptyDescription>
                Worker
                发现可疑点后会先登记候选（add_candidate），再验证、再上报漏洞。这里没有内容说明当前还没有值得跟进的路径。
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          items.map((c) => <CandidateCard candidate={c} key={c.id} onChanged={refresh} />)
        )}
      </CardContent>
    </Card>
  );
}
