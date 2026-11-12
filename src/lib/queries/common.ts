import type { DB } from "../db";
import type { Scan, Tag, Vulnerability, Workload } from "../db/schema";
import { type Diff, diffSummary, diffVulnerabilities } from "../trivy/diff";

/** Severity order used for sorting and "worst of": lower is worse. */
const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
export const severityRank = (s: string): number => RANK[s] ?? 4;
export const worstSeverity = (a: string, b: string): string => (severityRank(a) <= severityRank(b) ? a : b);

/** Sorts findings worst first, then by score, then by id. */
export function bySeverity<V extends { severity: string; score?: number | null; vuln_id: string; package?: string }>(
  a: V,
  b: V,
): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    (b.score ?? 0) - (a.score ?? 0) ||
    a.vuln_id.localeCompare(b.vuln_id) ||
    (a.package ?? "").localeCompare(b.package ?? "")
  );
}

/**
 * Orders two tags by their numeric runs, compared left to right as integers.
 * Positive when `a` is newer. This mirrors the plan's ordering rule, but only
 * to pick which candidate the UI shows first; the worker decides what is a
 * candidate. Ties fall through to the caller's tiebreak.
 */
export function compareTagVersions(a: string, b: string): number {
  const na = a.match(/\d+/g)?.map(Number) ?? [];
  const nb = b.match(/\d+/g)?.map(Number) ?? [];
  for (let i = 0; i < Math.max(na.length, nb.length); i++) {
    const x = na[i];
    const y = nb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x !== y) return x - y;
  }
  return 0;
}

/** Candidates first, newest first; then the rest, newest first. */
export function sortTags<T extends Pick<Tag, "tag" | "is_candidate" | "first_seen_at" | "id">>(tags: T[]): T[] {
  return [...tags].sort(
    (a, b) =>
      b.is_candidate - a.is_candidate ||
      compareTagVersions(b.tag, a.tag) ||
      b.first_seen_at.localeCompare(a.first_seen_at) ||
      b.id - a.id,
  );
}

/** Workloads still running (not marked gone). */
export async function liveWorkloads(
  db: DB,
  opts: { imageIds?: number[]; namespace?: string } = {},
): Promise<Workload[]> {
  if (opts.imageIds && opts.imageIds.length === 0) return [];
  let q = db.selectFrom("workloads").selectAll().where("gone_at", "is", null);
  if (opts.imageIds) q = q.where("image_id", "in", opts.imageIds);
  if (opts.namespace) q = q.where("namespace", "=", opts.namespace);
  return q.orderBy("namespace").orderBy("name").orderBy("container").execute();
}

export async function vulnsForDigests(db: DB, digestIds: number[]): Promise<Vulnerability[]> {
  if (digestIds.length === 0) return [];
  const out: Vulnerability[] = [];
  // Chunked to stay under SQLite's bound-parameter limit.
  for (let i = 0; i < digestIds.length; i += 500) {
    out.push(
      ...(await db
        .selectFrom("vulnerabilities")
        .selectAll()
        .where("digest_id", "in", digestIds.slice(i, i + 500))
        .execute()),
    );
  }
  return out;
}

/**
 * The union of the findings of several running digests, one per
 * (vuln_id, package) -- the diff's key. Where digests disagree, the row that
 * names a fixed version wins (so "a fix exists upstream" is not lost), then
 * the worse severity.
 */
export function unionVulns(rows: Vulnerability[]): Vulnerability[] {
  const out = new Map<string, Vulnerability>();
  for (const v of rows) {
    const k = `${v.vuln_id}\u0000${v.package}`;
    const cur = out.get(k);
    if (
      !cur ||
      (!cur.fixed_version && v.fixed_version) ||
      (!!cur.fixed_version === !!v.fixed_version && severityRank(v.severity) < severityRank(cur.severity))
    ) {
      out.set(k, v);
    }
  }
  return [...out.values()];
}

/** The newest scan per digest, for one or more images. */
export async function latestScansByDigest(db: DB, imageIds: number[]): Promise<Map<string, Scan>> {
  const out = new Map<string, Scan>();
  if (imageIds.length === 0) return out;
  const scans = await db.selectFrom("scans").selectAll().where("image_id", "in", imageIds).orderBy("id", "asc").execute();
  for (const s of scans) out.set(scanKey(s.image_id, s.digest), s);
  return out;
}
export const scanKey = (imageId: number, digest: string) => `${imageId}\u0000${digest}`;

export interface DiffCounts {
  fixed: number;
  stillPresent: number;
  introduced: number;
  /** "fixes 12, leaves 3, adds 1" */
  summary: string;
}

export function diffCounts(d: Diff<Vulnerability>): DiffCounts {
  return {
    fixed: d.fixed.length,
    stillPresent: d.stillPresent.length,
    introduced: d.introduced.length,
    summary: diffSummary(d),
  };
}

/**
 * Diff summaries for done scans, each against the union of its image's
 * running digests. Scans that are not done, have no result, or whose image has
 * no running digest get no entry.
 */
export async function summariesForScans(
  db: DB,
  scans: Scan[],
  runningDigestIdsByImage: Map<number, number[]>,
): Promise<Map<number, DiffCounts>> {
  const out = new Map<number, DiffCounts>();
  const done = scans.filter(
    (s) => s.status === "done" && s.result_digest_id != null && (runningDigestIdsByImage.get(s.image_id)?.length ?? 0) > 0,
  );
  if (done.length === 0) return out;
  const ids = new Set<number>();
  for (const s of done) {
    ids.add(s.result_digest_id!);
    for (const d of runningDigestIdsByImage.get(s.image_id)!) ids.add(d);
  }
  const byDigest = new Map<number, Vulnerability[]>();
  for (const v of await vulnsForDigests(db, [...ids])) {
    let list = byDigest.get(v.digest_id);
    if (!list) byDigest.set(v.digest_id, (list = []));
    list.push(v);
  }
  for (const s of done) {
    const running = unionVulns(runningDigestIdsByImage.get(s.image_id)!.flatMap((d) => byDigest.get(d) ?? []));
    const candidate = byDigest.get(s.result_digest_id!) ?? [];
    out.set(s.id, diffCounts(diffVulnerabilities(running, candidate)));
  }
  return out;
}

/** Distinct running digest ids per image, from live workloads. */
export function runningDigestsByImage(workloads: Pick<Workload, "image_id" | "digest_id">[]): Map<number, number[]> {
  const out = new Map<number, Set<number>>();
  for (const w of workloads) {
    if (w.digest_id == null) continue;
    let s = out.get(w.image_id);
    if (!s) out.set(w.image_id, (s = new Set()));
    s.add(w.digest_id);
  }
  return new Map([...out].map(([k, v]) => [k, [...v].sort((a, b) => a - b)]));
}

export interface CveCounts {
  critical: number;
  high: number;
  medium: number;
}

/**
 * Counts CVEs the way the Overview does: each vuln_id once, at the worst
 * severity any of its findings gives it. Used for the running image and for
 * each scanned candidate, so the two compare like for like.
 */
export function cveCounts(vulns: { vuln_id: string; severity: string }[]): CveCounts {
  const worst = new Map<string, string>();
  for (const v of vulns) {
    const cur = worst.get(v.vuln_id);
    worst.set(v.vuln_id, cur ? worstSeverity(cur, v.severity) : v.severity);
  }
  const out = { critical: 0, high: 0, medium: 0 };
  for (const s of worst.values()) {
    if (s === "CRITICAL") out.critical++;
    else if (s === "HIGH") out.high++;
    else if (s === "MEDIUM") out.medium++;
  }
  return out;
}
