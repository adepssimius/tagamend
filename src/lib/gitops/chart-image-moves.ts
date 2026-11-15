import type { ChartImage, ImageMoveTarget, ImageTagKey } from "../charts/types";
import { type DB, now } from "../db";
import type { Chart, ChartImagePr } from "../db/schema";
import { withSyncRun } from "../db/store";
import { errorMessage } from "../log";
import type { WorkerContext } from "../worker-context";
import { applySpans, type ChartEdit, ChartEditError, findDoc, planValueWrites } from "./chart-yaml";
import { gitHubClient } from "./github";
import type { PrQueueDeps } from "./queue";
import { readTarGz } from "./tar";

/**
 * Image moves: a PR that sets image tags in a HelmRelease's spec.values,
 * independent of the chart version. The chart check records which values key
 * sets each image's tag (charts.image_keys); this sets those keys, adding them
 * when the chart's defaults set the tag today.
 */

const parse = <T>(text: string | null): T[] => (text ? (JSON.parse(text) as T[]) : []);
export const chartImageKeys = (c: Chart) => parse<ImageTagKey>(c.image_keys);
export const imageMoveTargets = (p: ChartImagePr) => parse<ImageMoveTarget>(p.targets);

/** A tag a person typed: a registry tag, nothing else. */
const TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

/** Why an image cannot be moved from tagamend, or null when it can. */
export function moveBlocker(k: ImageTagKey | undefined): string | null {
  if (!k?.valuesPath) return "no values key sets this image's tag";
  if (k.digestHeld) return "the chart also pins a digest for it, so a new tag alone would not move it";
  if (k.origin?.startsWith("ConfigMap/")) return `its tag is set in valuesFrom ${k.origin}, which tagamend does not edit`;
  return null;
}

/**
 * The targets for a request: each image given a tag different from what runs,
 * checked against the recorded keys. Images that share one key must be given
 * the same tag. Throws with what is wrong, for the page to show.
 */
export function buildTargets(chart: Chart, tags: Record<string, string>): ImageMoveTarget[] {
  const images = new Map(parse<ChartImage>(chart.current_images).map((i) => [i.key, i]));
  const keys = new Map(chartImageKeys(chart).map((k) => [k.key, k]));
  const targets: ImageMoveTarget[] = [];
  const byPath = new Map<string, ImageMoveTarget>();
  for (const [key, raw] of Object.entries(tags)) {
    const to = raw.trim();
    const img = images.get(key);
    if (!to || !img || to === img.tag) continue;
    const label = `${img.kind}/${img.name}`;
    if (!TAG.test(to)) throw new Error(`${label}: "${to}" is not a valid image tag`);
    const k = keys.get(key);
    const blocked = moveBlocker(k);
    if (blocked) throw new Error(`${label} cannot be moved: ${blocked}`);
    const t: ImageMoveTarget = {
      key,
      kind: img.kind,
      name: img.name,
      registry: img.registry,
      repository: img.repository,
      valuesPath: k!.valuesPath!,
      from: img.tag,
      to,
    };
    const pathKey = JSON.stringify(t.valuesPath);
    const other = byPath.get(pathKey);
    if (other && other.to !== to) {
      throw new Error(
        `${label} and ${other.kind}/${other.name} are set by the same key (${t.valuesPath.join(".")}), so they take one tag; got ${to} and ${other.to}`,
      );
    }
    byPath.set(pathKey, t);
    targets.push(t);
  }
  // An image that shares a key with a moved one moves too; say so rather than surprise.
  for (const [key, img] of images) {
    if (targets.some((t) => t.key === key)) continue;
    const k = keys.get(key);
    const shared = k?.valuesPath ? byPath.get(JSON.stringify(k.valuesPath)) : undefined;
    if (shared && shared.to !== img.tag) {
      targets.push({ ...shared, key, kind: img.kind, name: img.name, registry: img.registry, repository: img.repository, from: img.tag });
    }
  }
  if (targets.length === 0) throw new Error("no image was given a new tag");
  return targets.sort((a, b) => a.key.localeCompare(b.key));
}

/**
 * Queues an image-move PR. Called by the web process. An identical request
 * that is queued, running or still open is returned instead of adding another.
 */
export async function queueImageMove(
  db: DB,
  req: { chartId: number; tags: Record<string, string>; requestedBy: string },
): Promise<{ pr: ChartImagePr; created: boolean }> {
  const chart = await db.selectFrom("charts").selectAll().where("id", "=", req.chartId).executeTakeFirst();
  if (!chart) throw new Error(`chart ${req.chartId} does not exist`);
  if (chart.gone_at) throw new Error(`HelmRelease ${chart.namespace}/${chart.name} no longer exists`);
  if (!chart.image_keys) throw new Error("the chart check has not found the values keys for these images yet");
  const targets = JSON.stringify(buildTargets(chart, req.tags));
  const existing = await db
    .selectFrom("chart_image_prs")
    .selectAll()
    .where("chart_id", "=", chart.id)
    .where("targets", "=", targets)
    .where("status", "in", ["queued", "running", "opened"])
    .where((eb) => eb.or([eb("pr_state", "is", null), eb("pr_state", "in", ["open", "draft"])]))
    .executeTakeFirst();
  if (existing) return { pr: existing, created: false };
  const pr = await db
    .insertInto("chart_image_prs")
    .values({
      chart_id: chart.id,
      targets,
      status: "queued",
      requested_by: req.requestedBy,
      requested_at: now(),
      started_at: null,
      finished_at: null,
      branch: null,
      pr_number: null,
      pr_url: null,
      pr_state: null,
      pr_state_checked_at: null,
      edits: null,
      error: null,
    })
    .returningAll()
    .executeTakeFirstOrThrow();
  return { pr, created: true };
}

/**
 * The edits that set each target's key under the HelmRelease's spec.values.
 * A key that exists must still hold the running tag the chart check saw (or
 * be empty); otherwise the repo moved on and the request fails.
 */
export function planImageMoves(
  files: Map<string, string>,
  opts: { namespace: string; name: string; targets: ImageMoveTarget[] },
): { files: Map<string, string>; edits: ChartEdit[] } {
  const hr = findDoc(files, "HelmRelease", opts.name, opts.namespace);
  if (hr.doc.getIn(["spec"]) === undefined) throw new ChartEditError(`HelmRelease ${opts.namespace}/${opts.name} (${hr.path}) has no spec`);
  const writes = new Map<string, { path: string[]; value: string; from: (string | null)[] }>();
  for (const t of opts.targets) {
    const k = JSON.stringify(t.valuesPath);
    const w = writes.get(k);
    if (w) w.from.push(t.from);
    else writes.set(k, { path: ["spec", "values", ...t.valuesPath], value: t.to, from: [t.from] });
  }
  const list = [...writes.values()];
  const source = files.get(hr.path)!;
  const { spans, current } = planValueWrites(hr, source, list);
  for (const [i, w] of list.entries()) {
    const was = current[i];
    if (was != null && was !== "" && !w.from.includes(was)) {
      throw new ChartEditError(
        `${w.path.join(".")} in ${hr.path} is \`${was}\`, not the running \`${w.from.join("`, `")}\` the chart check recorded; wait for the next chart check`,
      );
    }
  }
  const object = `HelmRelease/${hr.namespace ?? "?"}/${hr.name}`;
  const r = applySpans(hr.path, source, spans.map((s) => ({ ...s, object })));
  return { files: new Map([[hr.path, r.text]]), edits: r.edits };
}

const isYaml = (p: string) => /\.ya?ml$/.test(p);
const clean = (s: string) => s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "");

export function imageMoveBranch(release: string, targets: ImageMoveTarget[]): string {
  const tags = [...new Set(targets.map((t) => t.to))].join("-");
  return `tagamend/images-${clean(release)}-${clean(tags)}`.slice(0, 120).replace(/[-.]+$/, "");
}

/** "server v2.6.3 → v2.7.0, machine-learning v2.6.3 → v2.7.0" */
function summary(targets: ImageMoveTarget[]): string {
  return targets.map((t) => `${t.repository.split("/").pop()} ${t.from ?? "?"} → ${t.to}`).filter((v, i, a) => a.indexOf(v) === i).join(", ");
}

export function buildImageMoveContent(opts: {
  chart: Chart;
  targets: ImageMoveTarget[];
  edits: ChartEdit[];
  chartUrl: string | null;
  requestedBy: string | null;
}): { title: string; body: string; commitMessage: string } {
  const { chart, targets } = opts;
  const title = `${chart.name}: move images (${summary(targets)})`.slice(0, 250);
  const lines = [
    `Sets image tags in HelmRelease \`${chart.namespace}/${chart.name}\`'s values. The chart version (${chart.installed_version ?? chart.version}) does not change.`,
    "",
    "| Image | From | To | Values key |",
    "| --- | --- | --- | --- |",
    ...targets.map((t) => `| ${t.kind}/${t.name} (\`${t.registry}/${t.repository}\`) | \`${t.from ?? "?"}\` | \`${t.to}\` | \`${t.valuesPath.join(".")}\` |`),
    "",
    "A key that was not in the values before is added. Once set, a chart upgrade no longer moves these images; to go back to the chart's defaults, remove the keys.",
  ];
  if (opts.chartUrl) lines.push("", `Scan results for these tags: ${opts.chartUrl}`);
  lines.push("", "### Edits", "");
  for (const e of opts.edits) {
    if (e.added) lines.push(`- \`${e.path}\` after line ${e.line}: added`, "", "```yaml", e.after, "```", "");
    else lines.push(`- \`${e.path}:${e.line}\` (\`${e.field}\`): \`${e.before.trim()}\` to \`${e.after.trim()}\``);
  }
  if (opts.requestedBy) lines.push("", `Requested by ${opts.requestedBy} in tagamend.`);
  return { title, body: lines.join("\n"), commitMessage: `${title}\n\nRequested in tagamend.` };
}

/** Opens one queued image-move PR. Called by the PR queue when no other PR is queued. */
export async function runImageMoveQueue(ctx: WorkerContext, deps: PrQueueDeps = {}): Promise<Record<string, unknown>> {
  const { db, config } = ctx;
  if (!config.GITOPS_REPO) return { idle: true, disabled: true };
  const next = await db.selectFrom("chart_image_prs").selectAll().where("status", "=", "queued").orderBy("id").limit(1).executeTakeFirst();
  if (!next) return { idle: true };
  const claimed = await db
    .updateTable("chart_image_prs")
    .set({ status: "running", started_at: now() })
    .where("id", "=", next.id)
    .where("status", "=", "queued")
    .executeTakeFirst();
  if (Number(claimed.numUpdatedRows) === 0) return { idle: true };

  return (await withSyncRun(db, "pr_queue", async () => {
    try {
      const result = await openOne(ctx, next, deps);
      await db
        .updateTable("chart_image_prs")
        .set({ status: "opened", finished_at: now(), pr_state: "open", pr_state_checked_at: now(), ...result })
        .where("id", "=", next.id)
        .execute();
      ctx.log.info("image move pr opened", { pr: next.id, url: result.pr_url });
      return { opened: 1, kind: "images", url: result.pr_url };
    } catch (e) {
      await db
        .updateTable("chart_image_prs")
        .set({ status: "failed", finished_at: now(), error: errorMessage(e).slice(0, 2000) })
        .where("id", "=", next.id)
        .execute();
      ctx.log.warn("image move pr failed", { pr: next.id, error: errorMessage(e) });
      return { failed: 1, kind: "images" };
    }
  }))!;
}

async function openOne(ctx: WorkerContext, req: ChartImagePr, deps: PrQueueDeps) {
  const { db, config } = ctx;
  const repo = config.GITOPS_REPO!;
  if (!deps.github && !config.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN is not set");
  const github = deps.github ?? gitHubClient(repo, config.GITHUB_TOKEN!);
  const chart = await db.selectFrom("charts").selectAll().where("id", "=", req.chart_id).executeTakeFirst();
  if (!chart) throw new Error(`chart ${req.chart_id} no longer exists`);
  if (chart.gone_at) throw new Error(`HelmRelease ${chart.namespace}/${chart.name} no longer exists`);
  const targets = imageMoveTargets(req);

  const baseSha = await github.branchSha(config.GITOPS_BRANCH);
  const files = readTarGz(await github.tarball(baseSha), isYaml);
  let plan;
  try {
    plan = planImageMoves(files, { namespace: chart.namespace, name: chart.name, targets });
  } catch (e) {
    if (e instanceof ChartEditError) throw new Error(`${e.message} (in ${repo}@${config.GITOPS_BRANCH})`);
    throw e;
  }
  const base = (config.APP_URL ?? config.AUTH_URL)?.replace(/\/$/, "");
  const content = buildImageMoveContent({ chart, targets, edits: plan.edits, chartUrl: base ? `${base}/charts/${chart.id}` : null, requestedBy: req.requested_by });

  const edits = JSON.stringify(plan.edits);
  let branch = imageMoveBranch(chart.name, targets);
  const open = await github.findOpenPr(branch);
  if (open) return { edits, branch, pr_number: open.number, pr_url: open.url };
  if (await github.branchExists(branch)) branch = `${branch}-${req.id}`;
  await github.commitToNewBranch({ baseSha, branch, message: content.commitMessage, files: plan.files });
  const pr = await github.openPr({ head: branch, base: config.GITOPS_BRANCH, title: content.title, body: content.body });
  return { edits, branch, pr_number: pr.number, pr_url: pr.url };
}
