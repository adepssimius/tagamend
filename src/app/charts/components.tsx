import { PrLink } from "@/components/pr-link";
import { ErrorText, mutedClass } from "@/components/ui";
import type { ChartPullRequest } from "@/lib/db/schema";
import type { CandidateScanState } from "@/lib/queries/charts";

/** One chart PR request: its link and state, its progress, or its failure. */
export function ChartPrState({ pr, short = false }: { pr: ChartPullRequest; short?: boolean }) {
  if (pr.status === "opened" && pr.pr_url && pr.pr_number != null) {
    return <PrLink number={pr.pr_number} url={pr.pr_url} state={pr.pr_state} />;
  }
  if (pr.status === "queued" || pr.status === "running") {
    return <span className={`text-xs ${mutedClass}`}>{pr.status === "queued" ? "queued" : "opening…"}</span>;
  }
  if (short) {
    return (
      <span className="text-xs text-red-700 dark:text-red-400" title={pr.error ?? undefined}>
        PR failed
      </span>
    );
  }
  return pr.error ? <ErrorText>{pr.error}</ErrorText> : <span className="text-xs text-red-700 dark:text-red-400">failed</span>;
}

/** "2/3 scanned": how many of the images a candidate changes have a done scan. */
export function ChartScanState({ state }: { state: CandidateScanState }) {
  if (state.state === "n/a") return <span className={`text-xs ${mutedClass}`}>—</span>;
  const cls =
    state.state === "all"
      ? "text-emerald-700 dark:text-emerald-400"
      : state.state === "partial"
        ? "text-amber-700 dark:text-amber-300"
        : mutedClass;
  return (
    <span className={`whitespace-nowrap text-xs tabular-nums ${cls}`} title="Images with a done scan, of the images with a digest to scan">
      {state.state === "none" ? "not scanned" : `${state.scanned}/${state.scannable} scanned`}
    </span>
  );
}

/** Known-exploited count: red when any. */
export function Exploited({ n }: { n: number }) {
  return n > 0 ? (
    <span className="font-semibold tabular-nums text-red-700 dark:text-red-400">{n}</span>
  ) : (
    <span className="tabular-nums text-zinc-300 dark:text-zinc-700">0</span>
  );
}

/** The change against what runs now: fewer is green, more is red. */
export function Delta({ n }: { n: number }) {
  if (n === 0) return null;
  return (
    <span className={`ml-1 text-xs tabular-nums ${n < 0 ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"}`}>
      {n < 0 ? `−${-n}` : `+${n}`}
    </span>
  );
}

/** A chart source without the scheme; the full URL in the tooltip. `hostOnly` keeps just the host, for dense tables. */
export function SourceName({ url, hostOnly = false }: { url: string; hostOnly?: boolean }) {
  const rest = url.replace(/^(https?|oci):\/\//, "").replace(/\/$/, "");
  const short = hostOnly ? rest.split("/")[0] : rest;
  return (
    <span className={`font-mono ${hostOnly ? "whitespace-nowrap" : "break-all"}`} title={url}>
      {url.startsWith("oci://") && <span className={mutedClass}>oci </span>}
      {short}
    </span>
  );
}
