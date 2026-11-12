import { now } from "../db";
import type { PullRequest } from "../db/schema";
import { withSyncRun } from "../db/store";
import { errorMessage } from "../log";
import { liveWorkloads } from "../queries/common";
import { kevFor } from "../queries/kev";
import { getScanPage } from "../queries/scan";
import type { WorkerContext } from "../worker-context";
import { type GitHub, gitHubClient } from "./github";
import { applyEdits, findImageEdits } from "./locate";
import { buildPrContent } from "./pr-body";
import { readTarGz } from "./tar";

const isYaml = (p: string) => /\.ya?ml$/.test(p);

/** Branch names GitHub accepts: `tagamend/<app>-<tag>`. */
export function branchName(repository: string, toTag: string, pinDigest?: string): string {
  const clean = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "");
  const pin = pinDigest ? `-${pinDigest.replace(/^sha256:/, "").slice(0, 12)}` : "";
  return `tagamend/${clean(repository.split("/").pop()!)}-${clean(toTag)}${pin}`;
}

export interface PrQueueDeps {
  github?: GitHub;
}

/**
 * Opens queued GitOps PRs, one per tick. Each request reads the base branch
 * once as a tarball, finds the image's references, commits the edits to a new
 * branch, and opens a PR whose body carries the candidate scan's diff.
 *
 * A request that finds nothing to change fails with the references it saw, so
 * an image that comes from a chart's defaults says so instead of opening an
 * empty PR.
 */
export async function runPrQueue(ctx: WorkerContext, deps: PrQueueDeps = {}): Promise<Record<string, unknown>> {
  const { db, config } = ctx;
  if (!config.GITOPS_REPO) return { idle: true, disabled: true };
  const next = await db
    .selectFrom("pull_requests")
    .selectAll()
    .where("status", "=", "queued")
    .orderBy("id")
    .limit(1)
    .executeTakeFirst();
  if (!next) return { idle: true };

  const claimed = await db
    .updateTable("pull_requests")
    .set({ status: "running", started_at: now() })
    .where("id", "=", next.id)
    .where("status", "=", "queued")
    .executeTakeFirst();
  if (Number(claimed.numUpdatedRows) === 0) return { idle: true };

  return (await withSyncRun(db, "pr_queue", async () => {
    try {
      const result = await openOne(ctx, next, deps);
      await db
        .updateTable("pull_requests")
        .set({ status: "opened", finished_at: now(), pr_state: "open", pr_state_checked_at: now(), ...result })
        .where("id", "=", next.id)
        .execute();
      ctx.log.info("pr opened", { pr: next.id, url: result.pr_url });
      return { opened: 1, url: result.pr_url };
    } catch (e) {
      const partial = e instanceof PrFailure ? e.partial : {};
      await db
        .updateTable("pull_requests")
        .set({ status: "failed", finished_at: now(), error: errorMessage(e).slice(0, 2000), ...partial })
        .where("id", "=", next.id)
        .execute();
      ctx.log.warn("pr failed", { pr: next.id, error: errorMessage(e) });
      return { failed: 1 };
    }
  }))!;
}

class PrFailure extends Error {
  constructor(
    message: string,
    readonly partial: Partial<Pick<PullRequest, "edits" | "skipped" | "branch">>,
  ) {
    super(message);
  }
}

async function openOne(ctx: WorkerContext, req: PullRequest, deps: PrQueueDeps) {
  const { db, config } = ctx;
  const repo = config.GITOPS_REPO!;
  if (!deps.github && !config.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN is not set");
  const github = deps.github ?? gitHubClient(repo, config.GITHUB_TOKEN!);

  const image = await db.selectFrom("images").selectAll().where("id", "=", req.image_id).executeTakeFirstOrThrow();
  const live = await liveWorkloads(db, { imageIds: [image.id] });
  const fromTags = [...new Set(live.map((w) => w.tag).filter((t): t is string => !!t))];
  if (fromTags.length === 0) throw new Error("no running workload has a tag to move");

  const page = await getScanPage(db, req.scan_id);
  if (!page?.diff) throw new Error(`scan ${req.scan_id} has no diff against the running image`);

  const baseSha = await github.branchSha(config.GITOPS_BRANCH);
  const files = readTarGz(await github.tarball(baseSha), isYaml);
  // The same tag at a newer digest (a moved floating tag): pin the digest.
  const pinDigest = fromTags.includes(req.to_tag) ? req.to_digest : undefined;
  const { edits, skipped } = findImageEdits(files, {
    registry: image.registry,
    repository: image.repository,
    fromTags,
    toTag: req.to_tag,
    pinDigest,
  });
  const partial = { edits: JSON.stringify(edits), skipped: JSON.stringify(skipped) };
  if (edits.length === 0) {
    const why = skipped.length
      ? `references found, none movable: ${skipped.map((s) => `${s.path}:${s.line} (${s.reason})`).join("; ")}`
      : `no reference to ${image.registry}/${image.repository} in ${repo}. It may come from a Helm chart's defaults, which a chart version bump changes, or be deployed from outside the repo.`;
    throw new PrFailure(why, partial);
  }

  // The title names the tags that actually moved, not every running tag.
  const movedFrom = [...new Set(edits.map((e) => e.fromTag))];
  const base = (config.APP_URL ?? config.AUTH_URL)?.replace(/\/$/, "");
  const d = page.diff;
  const kev = await kevFor(db, [...d.fixed, ...d.introduced, ...d.stillPresent.map((s) => s.running)].map((v) => v.vuln_id));
  const content = buildPrContent({
    repository: image.repository,
    registry: image.registry,
    fromTags: movedFrom,
    toTag: req.to_tag,
    toDigest: req.to_digest,
    diff: page.diff,
    edits,
    skipped,
    scanUrl: base ? `${base}/scans/${req.scan_id}` : null,
    requestedBy: req.requested_by,
    exploited: new Set(kev.keys()),
    pinned: !!pinDigest,
  });

  let branch = branchName(image.repository, req.to_tag, pinDigest);
  const open = await github.findOpenPr(branch);
  if (open) return { ...partial, branch, pr_number: open.number, pr_url: open.url };
  if (await github.branchExists(branch)) branch = `${branch}-${req.id}`;

  await github.commitToNewBranch({
    baseSha,
    branch,
    message: content.commitMessage,
    files: applyEdits(files, edits),
  });
  const pr = await github.openPr({ head: branch, base: config.GITOPS_BRANCH, title: content.title, body: content.body });
  return { ...partial, branch, pr_number: pr.number, pr_url: pr.url };
}

