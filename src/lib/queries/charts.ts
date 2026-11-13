import type { DB } from "../db";
import type { Chart, ChartCandidate, ChartPullRequest, Scan, Workload } from "../db/schema";
import { type ChartChangeDiff, chartCandidateDiff } from "../charts/diff";
import type { ChartImage, ChartImageChange, PinnedImage } from "../charts/types";
import { compareTagVersions, type CveCounts, cveCounts, liveWorkloads, scanKey, unionVulns, vulnsForDigests } from "./common";
import { kevFor } from "./kev";

/** How a workload's managed_by names a HelmRelease. */
export const helmReleaseRef = (c: { namespace: string; name: string }) => `HelmRelease ${c.namespace}/${c.name}`;

/** The HelmRelease a workload's managed_by names, or null for a Kustomization, "none" or unknown. */
export function parseHelmRelease(managedBy: string | null): { namespace: string; name: string } | null {
  const m = managedBy?.match(/^HelmRelease ([^/\s]+)\/(\S+)$/);
  return m ? { namespace: m[1]!, name: m[2]! } : null;
}

/** "none": nothing scanned; "partial": some; "all": every image the candidate changes; "n/a": nothing to scan. */
export type ScanState = "none" | "partial" | "all" | "n/a";

export interface CandidateScanState {
  /** Images the candidate changes, counting each new image once. */
  changed: number;
  /** Of those, the ones with a digest to scan. */
  scannable: number;
  /** Of those, the ones with a done scan. */
  scanned: number;
  state: ScanState;
}

export interface ChartListRow {
  chart: Chart;
  /** Live workloads the HelmRelease applies. */
  workloads: number;
  /** CVEs in the HelmRelease's images now: per image, each CVE once at its worst severity; summed across images. */
  running: CveCounts;
  candidateCount: number;
  /** The newest candidate version. */
  best: (CandidateScanState & { candidate: ChartCandidate }) | null;
  /** The newest chart PR request for this HelmRelease. */
  pr: ChartPullRequest | null;
}

const parse = <T>(text: string | null): T[] => (text ? (JSON.parse(text) as T[]) : []);
export const candidateChanges = (c: ChartCandidate) => parse<ChartImageChange>(c.changes);
export const candidatePins = (c: ChartCandidate) => parse<PinnedImage>(c.pinned);
export const chartCurrentImages = (c: Chart) => parse<ChartImage>(c.current_images);

/** Candidates newest first; the rest after, newest first. */
export function sortChartCandidates<T extends Pick<ChartCandidate, "version" | "is_candidate" | "first_seen_at" | "id">>(rows: T[]): T[] {
  return [...rows].sort(
    (a, b) =>
      b.is_candidate - a.is_candidate ||
      compareTagVersions(b.version, a.version) ||
      b.first_seen_at.localeCompare(a.first_seen_at) ||
      b.id - a.id,
  );
}

/** The image ids by "registry/repository". */
async function imageIds(db: DB): Promise<Map<string, number>> {
  const rows = await db.selectFrom("images").select(["id", "registry", "repository"]).execute();
  return new Map(rows.map((r) => [`${r.registry}/${r.repository}`, r.id]));
}

/** The newest scan for each (image, digest) among `digests`. */
async function scansForDigests(db: DB, digests: string[]): Promise<Map<string, Scan>> {
  const out = new Map<string, Scan>();
  const unique = [...new Set(digests)];
  for (let i = 0; i < unique.length; i += 500) {
    const rows = await db.selectFrom("scans").selectAll().where("digest", "in", unique.slice(i, i + 500)).orderBy("id", "asc").execute();
    for (const s of rows) out.set(scanKey(s.image_id, s.digest), s);
  }
  return out;
}

/** The digests a candidate's changed images would run, as (registry, repository, digest). */
function scanTargets(changes: ChartImageChange[]): ChartImage[] {
  const seen = new Map<string, ChartImage>();
  for (const ch of changes) {
    if (ch.to?.digest) seen.set(`${ch.to.registry}/${ch.to.repository}@${ch.to.digest}`, ch.to);
  }
  return [...seen.values()];
}

function scanStateOf(changes: ChartImageChange[], ids: Map<string, number>, scans: Map<string, Scan>): CandidateScanState {
  const targets = scanTargets(changes);
  let scanned = 0;
  let started = 0;
  for (const t of targets) {
    const id = ids.get(`${t.registry}/${t.repository}`);
    const s = id != null ? scans.get(scanKey(id, t.digest!)) : undefined;
    if (s) started++;
    if (s?.status === "done") scanned++;
  }
  const changed = new Set(changes.map((c) => c.key)).size;
  const state: ScanState =
    targets.length === 0 ? "n/a" : scanned === targets.length ? "all" : started === 0 ? "none" : "partial";
  return { changed, scannable: targets.length, scanned, state };
}

/** CVE counts across workloads, each image's digests unioned, then summed across images. */
async function countsForWorkloads(db: DB, workloads: Workload[]): Promise<CveCounts> {
  const byImage = new Map<number, Set<number>>();
  for (const w of workloads) {
    if (w.digest_id == null) continue;
    let s = byImage.get(w.image_id);
    if (!s) byImage.set(w.image_id, (s = new Set()));
    s.add(w.digest_id);
  }
  const vulns = await vulnsForDigests(db, [...byImage.values()].flatMap((s) => [...s]));
  const kev = new Set((await kevFor(db, vulns.map((v) => v.vuln_id))).keys());
  const total = { critical: 0, high: 0, medium: 0, exploited: 0 };
  for (const digests of byImage.values()) {
    const c = cveCounts(unionVulns(vulns.filter((v) => digests.has(v.digest_id))), kev);
    total.critical += c.critical;
    total.high += c.high;
    total.medium += c.medium;
    total.exploited += c.exploited;
  }
  return total;
}

/**
 * One row per HelmRelease that still exists. Ones with a candidate come
 * first; within each group the worst running CVEs first.
 */
export async function getChartList(db: DB): Promise<ChartListRow[]> {
  const charts = await db.selectFrom("charts").selectAll().where("gone_at", "is", null).execute();
  if (charts.length === 0) return [];
  const [candidates, prs, live, ids] = await Promise.all([
    db.selectFrom("chart_candidates").selectAll().where("is_candidate", "=", 1).execute(),
    db.selectFrom("chart_pull_requests").selectAll().orderBy("id", "desc").execute(),
    liveWorkloads(db),
    imageIds(db),
  ]);
  const bestByChart = new Map<number, ChartCandidate>();
  const countByChart = new Map<number, number>();
  for (const c of sortChartCandidates(candidates)) {
    countByChart.set(c.chart_id, (countByChart.get(c.chart_id) ?? 0) + 1);
    if (!bestByChart.has(c.chart_id)) bestByChart.set(c.chart_id, c);
  }
  const scans = await scansForDigests(
    db,
    [...bestByChart.values()].flatMap((c) => scanTargets(candidateChanges(c)).map((t) => t.digest!)),
  );

  const rows: ChartListRow[] = [];
  for (const chart of charts) {
    const ref = helmReleaseRef(chart);
    const workloads = live.filter((w) => w.managed_by === ref);
    const best = bestByChart.get(chart.id);
    rows.push({
      chart,
      workloads: new Set(workloads.map((w) => `${w.namespace}/${w.kind}/${w.name}`)).size,
      running: await countsForWorkloads(db, workloads),
      candidateCount: countByChart.get(chart.id) ?? 0,
      best: best ? { candidate: best, ...scanStateOf(candidateChanges(best), ids, scans) } : null,
      pr: prs.find((p) => p.chart_id === chart.id) ?? null,
    });
  }
  return rows.sort(
    (a, b) =>
      Number(!!b.best) - Number(!!a.best) ||
      b.running.exploited - a.running.exploited ||
      b.running.critical - a.running.critical ||
      b.running.high - a.running.high ||
      b.running.medium - a.running.medium ||
      a.chart.namespace.localeCompare(b.chart.namespace) ||
      a.chart.name.localeCompare(b.chart.name),
  );
}

export interface ChartCandidateRow extends CandidateScanState {
  candidate: ChartCandidate;
  changes: ChartImageChange[];
  pinned: PinnedImage[];
  /** Chart PR requests for this candidate, newest first. */
  prs: ChartPullRequest[];
}

export interface PinnedRow {
  pin: PinnedImage;
  /** The chart default's running/candidate counts and diff, as for a change. Null with no default image. */
  diff: ChartChangeDiff | null;
}

export interface ChartPage {
  chart: Chart;
  /** Live workloads the HelmRelease applies. */
  workloads: Workload[];
  running: CveCounts;
  /** The images the installed version renders, with their image ids when known. */
  currentImages: (ChartImage & { imageId: number | null })[];
  /** Candidates, newest first. */
  candidates: ChartCandidateRow[];
  /** Versions seen that are not candidates, with the reason. */
  others: ChartCandidate[];
  /** The candidate shown in detail: the one asked for, else the newest. */
  selected: (ChartCandidateRow & { diffs: ChartChangeDiff[]; pins: PinnedRow[] }) | null;
}

export async function getChartPage(db: DB, chartId: number, candidateId?: number): Promise<ChartPage | null> {
  const chart = await db.selectFrom("charts").selectAll().where("id", "=", chartId).executeTakeFirst();
  if (!chart) return null;
  const [all, prs, live, ids] = await Promise.all([
    db.selectFrom("chart_candidates").selectAll().where("chart_id", "=", chartId).execute(),
    db.selectFrom("chart_pull_requests").selectAll().where("chart_id", "=", chartId).orderBy("id", "desc").execute(),
    liveWorkloads(db, { namespace: chart.namespace }),
    imageIds(db),
  ]);
  const workloads = live.filter((w) => w.managed_by === helmReleaseRef(chart));
  const sorted = sortChartCandidates(all);
  const cands = sorted.filter((c) => c.is_candidate);
  const scans = await scansForDigests(db, cands.flatMap((c) => scanTargets(candidateChanges(c)).map((t) => t.digest!)));
  const candidates: ChartCandidateRow[] = cands.map((c) => {
    const changes = candidateChanges(c);
    return {
      candidate: c,
      changes,
      pinned: candidatePins(c),
      prs: prs.filter((p) => p.candidate_id === c.id),
      ...scanStateOf(changes, ids, scans),
    };
  });

  // The asked-for candidate may be a non-candidate version; show it too.
  let pick = candidateId != null ? candidates.find((c) => c.candidate.id === candidateId) : candidates[0];
  if (!pick && candidateId != null) {
    const other = sorted.find((c) => c.id === candidateId);
    if (other) {
      const changes = candidateChanges(other);
      pick = { candidate: other, changes, pinned: candidatePins(other), prs: prs.filter((p) => p.candidate_id === other.id), ...scanStateOf(changes, ids, scans) };
    }
  }
  let selected: ChartPage["selected"] = null;
  if (pick) {
    const diffs = await chartCandidateDiff(db, chart, pick.candidate);
    // A pin compares like a change: what runs now against the chart's default image.
    const withDefault = pick.pinned.filter((p) => p.chartDefault);
    const pinDiffs = withDefault.length
      ? await chartCandidateDiff(db, chart, {
          ...pick.candidate,
          changes: JSON.stringify(
            withDefault.map((p): ChartImageChange => ({ key: p.key, kind: p.kind, name: p.name, from: null, to: p.chartDefault })),
          ),
        })
      : [];
    const pins = pick.pinned.map((pin) => ({ pin, diff: pin.chartDefault ? (pinDiffs[withDefault.indexOf(pin)] ?? null) : null }));
    selected = { ...pick, diffs, pins };
  }

  return {
    chart,
    workloads,
    running: await countsForWorkloads(db, workloads),
    currentImages: chartCurrentImages(chart).map((i) => ({ ...i, imageId: ids.get(`${i.registry}/${i.repository}`) ?? null })),
    candidates,
    others: sorted.filter((c) => !c.is_candidate),
    selected,
  };
}

/** Chart ids by the managed_by string that names their HelmRelease, for the given values. */
export async function chartIdsByManagedBy(db: DB, managedBy: (string | null)[]): Promise<Map<string, number>> {
  const refs = [...new Set(managedBy.map(parseHelmRelease).filter((r) => r != null).map((r) => helmReleaseRef(r!)))];
  const out = new Map<string, number>();
  if (refs.length === 0) return out;
  const namespaces = [...new Set(refs.map((r) => parseHelmRelease(r)!.namespace))];
  const rows = await db
    .selectFrom("charts")
    .select(["id", "namespace", "name"])
    .where("namespace", "in", namespaces)
    .where("gone_at", "is", null)
    .execute();
  for (const r of rows) {
    const ref = helmReleaseRef(r);
    if (refs.includes(ref)) out.set(ref, r.id);
  }
  return out;
}

/** How many live HelmReleases have a newer chart version, for the Overview. */
export async function chartsWithCandidate(db: DB): Promise<number> {
  const row = await db
    .selectFrom("charts")
    .where("gone_at", "is", null)
    .where((eb) =>
      eb.exists(
        eb
          .selectFrom("chart_candidates")
          .select("chart_candidates.id")
          .whereRef("chart_candidates.chart_id", "=", "charts.id")
          .where("chart_candidates.is_candidate", "=", 1),
      ),
    )
    .select((eb) => eb.fn.countAll<number>().as("n"))
    .executeTakeFirstOrThrow();
  return Number(row.n);
}
