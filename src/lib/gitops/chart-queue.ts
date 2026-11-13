import { chartCandidateDiff } from "../charts/diff";
import type { PinnedImage } from "../charts/types";
import { now } from "../db";
import type { ChartPullRequest } from "../db/schema";
import { withSyncRun } from "../db/store";
import { errorMessage } from "../log";
import { kevFor } from "../queries/kev";
import type { WorkerContext } from "../worker-context";
import { planChartEdits } from "./chart-edits";
import { buildChartPrContent } from "./chart-pr-body";
import { ChartEditError } from "./chart-yaml";
import { gitHubClient } from "./github";
import type { PrQueueDeps } from "./queue";
import { readTarGz } from "./tar";

const isYaml = (p: string) => /\.ya?ml$/.test(p);
const clean = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "");

/** Branch names GitHub accepts: `tagamend/chart-<release>-<version>`, with `-pins` when pinned tags move too. */
export function chartBranchName(release: string, version: string, movesPins: boolean): string {
  return `tagamend/chart-${clean(release)}-${clean(version)}${movesPins ? "-pins" : ""}`;
}

/**
 * Opens one queued chart upgrade PR. Called by the PR queue when it has no
 * image tag PR to open, so both kinds share one worker loop. Reads the base
 * branch as a tarball, edits the chart version (and, when asked, the pinned
 * image tags) in place, commits to a new branch and opens the PR.
 */
export async function runChartPrQueue(ctx: WorkerContext, deps: PrQueueDeps = {}): Promise<Record<string, unknown>> {
  const { db, config } = ctx;
  if (!config.GITOPS_REPO) return { idle: true, disabled: true };
  const next = await db
    .selectFrom("chart_pull_requests")
    .selectAll()
    .where("status", "=", "queued")
    .orderBy("id")
    .limit(1)
    .executeTakeFirst();
  if (!next) return { idle: true };

  const claimed = await db
    .updateTable("chart_pull_requests")
    .set({ status: "running", started_at: now() })
    .where("id", "=", next.id)
    .where("status", "=", "queued")
    .executeTakeFirst();
  if (Number(claimed.numUpdatedRows) === 0) return { idle: true };

  return (await withSyncRun(db, "pr_queue", async () => {
    try {
      const result = await openOne(ctx, next, deps);
      await db
        .updateTable("chart_pull_requests")
        .set({ status: "opened", finished_at: now(), pr_state: "open", pr_state_checked_at: now(), ...result })
        .where("id", "=", next.id)
        .execute();
      ctx.log.info("chart pr opened", { pr: next.id, url: result.pr_url });
      return { opened: 1, kind: "chart", url: result.pr_url };
    } catch (e) {
      await db
        .updateTable("chart_pull_requests")
        .set({ status: "failed", finished_at: now(), error: errorMessage(e).slice(0, 2000) })
        .where("id", "=", next.id)
        .execute();
      ctx.log.warn("chart pr failed", { pr: next.id, error: errorMessage(e) });
      return { failed: 1, kind: "chart" };
    }
  }))!;
}

async function openOne(ctx: WorkerContext, req: ChartPullRequest, deps: PrQueueDeps) {
  const { db, config } = ctx;
  const repo = config.GITOPS_REPO!;
  if (!deps.github && !config.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN is not set");
  const github = deps.github ?? gitHubClient(repo, config.GITHUB_TOKEN!);

  const chart = await db.selectFrom("charts").selectAll().where("id", "=", req.chart_id).executeTakeFirst();
  if (!chart) throw new Error(`chart ${req.chart_id} no longer exists`);
  if (chart.gone_at) throw new Error(`HelmRelease ${chart.namespace}/${chart.name} no longer exists`);
  const candidate = await db.selectFrom("chart_candidates").selectAll().where("id", "=", req.candidate_id).executeTakeFirst();
  if (!candidate) throw new Error(`chart candidate ${req.candidate_id} no longer exists`);
  const pins = candidate.pinned ? (JSON.parse(candidate.pinned) as PinnedImage[]) : [];

  const baseSha = await github.branchSha(config.GITOPS_BRANCH);
  const files = readTarGz(await github.tarball(baseSha), isYaml);
  let plan;
  try {
    plan = planChartEdits(files, {
      namespace: chart.namespace,
      name: chart.name,
      toVersion: req.to_version,
      pins,
      updatePins: !!req.update_pins,
    });
  } catch (e) {
    if (e instanceof ChartEditError) throw new Error(`${e.message} (in ${repo}@${config.GITOPS_BRANCH})`);
    throw e;
  }

  const diffs = await chartCandidateDiff(db, chart, candidate);
  const vulnIds = diffs.flatMap((d) =>
    d.diff ? [...d.diff.fixed, ...d.diff.introduced, ...d.diff.stillPresent.map((s) => s.running)].map((v) => v.vuln_id) : [],
  );
  const exploited = new Set((await kevFor(db, vulnIds)).keys());
  const base = (config.APP_URL ?? config.AUTH_URL)?.replace(/\/$/, "");
  const content = buildChartPrContent({
    chart,
    toVersion: req.to_version,
    plan,
    diffs,
    exploited,
    chartUrl: base ? `${base}/charts/${chart.id}` : null,
    requestedBy: req.requested_by,
  });

  const edits = JSON.stringify(plan.edits);
  let branch = chartBranchName(chart.name, req.to_version, plan.pins.some((p) => p.outcome === "moved"));
  const open = await github.findOpenPr(branch);
  if (open) return { edits, branch, pr_number: open.number, pr_url: open.url };
  if (await github.branchExists(branch)) branch = `${branch}-${req.id}`;

  await github.commitToNewBranch({ baseSha, branch, message: content.commitMessage, files: plan.files });
  const pr = await github.openPr({ head: branch, base: config.GITOPS_BRANCH, title: content.title, body: content.body });
  return { edits, branch, pr_number: pr.number, pr_url: pr.url };
}
