import { sql } from "kysely";
import type { DB } from "../db";
import type { ScanStatus } from "../db/schema";
import { parseTag } from "../registry/tag-shape";
import {
  type DiffCounts,
  latestScansByDigest,
  liveWorkloads,
  runningDigestsByImage,
  scanKey,
  sortTags,
  summariesForScans,
} from "./common";

export type MinSeverity = "CRITICAL" | "HIGH" | "MEDIUM";
export const SORT_KEYS = ["image", "workloads", "critical", "high", "medium", "candidate"] as const;
export type SortKey = (typeof SORT_KEYS)[number];

export interface OverviewOptions {
  /** Only workloads in this namespace count: their tags, digests and CVEs. */
  namespace?: string;
  minSeverity?: MinSeverity;
  hasCandidate?: boolean;
  /** Default: worst first (critical, then high, then medium). */
  sort?: SortKey;
  dir?: "asc" | "desc";
}

export interface OverviewRow {
  imageId: number;
  registry: string;
  repository: string;
  /** Distinct running tags; null means a workload runs the image by digest only. */
  tags: (string | null)[];
  workloads: number;
  namespaces: string[];
  /** Distinct running digests. More than one means the counts are a union. */
  digests: number;
  critical: number;
  high: number;
  medium: number;
  candidateCount: number;
  /** Tag discovery state for the image, so "no candidate" can say why. */
  tagCheck: {
    checkedAt: string | null;
    error: string | null;
    /** Every running tag is a digest pin: nothing to compare. */
    pinned: boolean;
    /** Every running tag is floating (latest, stable): only digest drift is checked. */
    floating: boolean;
  };
  candidate: {
    tag: string;
    reason: string | null;
    hasDigest: boolean;
    scan: { id: number; status: ScanStatus; diff: DiffCounts | null } | null;
  } | null;
}

export interface Overview {
  rows: OverviewRow[];
  totals: {
    images: number;
    workloads: number;
    critical: number;
    high: number;
    medium: number;
    withCandidate: number;
    candidatesScanned: number;
    /** Images tag discovery has checked at least once. */
    tagsChecked: number;
  };
  /** Namespaces with live workloads, for the filter. Not affected by filters. */
  namespaces: string[];
  lastReportSync: { finished_at: string | null; ok: number | null } | null;
}

/**
 * Per-image CVE counts over the running digests.
 *
 * Each CVE counts once per image: the findings of every running digest are
 * pooled and grouped by vuln_id, so a CVE present in two digests, or in two
 * packages of one digest, counts once. Its severity is the worst any finding
 * gives it. This is the union of the running digests, which is what an
 * operator has to fix to clear the image, and matches the Grafana dashboard's
 * per-image counting. It deliberately differs from image_digests.critical/...,
 * which count findings (vuln_id x package) for a single digest.
 */
async function severityCounts(db: DB, namespace: string | undefined) {
  const rows = await db
    .with("live", (qb) => {
      let q = qb
        .selectFrom("workloads")
        .select(["image_id", "digest_id"])
        .distinct()
        .where("gone_at", "is", null)
        .where("digest_id", "is not", null);
      if (namespace) q = q.where("namespace", "=", namespace);
      return q;
    })
    .with("per_cve", (qb) =>
      qb
        .selectFrom("live")
        .innerJoin("vulnerabilities as v", "v.digest_id", "live.digest_id")
        .select([
          "live.image_id as image_id",
          "v.vuln_id as vuln_id",
          sql<number>`min(case v.severity when 'CRITICAL' then 0 when 'HIGH' then 1 when 'MEDIUM' then 2 when 'LOW' then 3 else 4 end)`.as(
            "sev_rank",
          ),
        ])
        .groupBy(["live.image_id", "v.vuln_id"]),
    )
    .selectFrom("per_cve")
    .select([
      "image_id",
      sql<number>`sum(case when sev_rank = 0 then 1 else 0 end)`.as("critical"),
      sql<number>`sum(case when sev_rank = 1 then 1 else 0 end)`.as("high"),
      sql<number>`sum(case when sev_rank = 2 then 1 else 0 end)`.as("medium"),
    ])
    .groupBy("image_id")
    .execute();
  // Postgres returns sum() as bigint, which pg hands back as a string.
  return new Map(
    rows.map((r) => [Number(r.image_id), { critical: Number(r.critical), high: Number(r.high), medium: Number(r.medium) }]),
  );
}

export async function getOverview(db: DB, opts: OverviewOptions = {}): Promise<Overview> {
  const [allLive, counts, lastReportSync] = await Promise.all([
    liveWorkloads(db),
    severityCounts(db, opts.namespace),
    db
      .selectFrom("sync_runs")
      .select(["finished_at", "ok"])
      .where("name", "=", "report_sync")
      .orderBy("id", "desc")
      .limit(1)
      .executeTakeFirst(),
  ]);
  const namespaces = [...new Set(allLive.map((w) => w.namespace))].sort();
  const live = opts.namespace ? allLive.filter((w) => w.namespace === opts.namespace) : allLive;

  const byImage = new Map<number, typeof live>();
  for (const w of live) {
    let list = byImage.get(w.image_id);
    if (!list) byImage.set(w.image_id, (list = []));
    list.push(w);
  }
  const imageIds = [...byImage.keys()];
  if (imageIds.length === 0) {
    return { rows: [], totals: emptyTotals(), namespaces, lastReportSync: lastReportSync ?? null };
  }

  const [images, tags, scansByDigest] = await Promise.all([
    db.selectFrom("images").selectAll().where("id", "in", imageIds).execute(),
    db.selectFrom("tags").selectAll().where("image_id", "in", imageIds).where("is_candidate", "=", 1).execute(),
    latestScansByDigest(db, imageIds),
  ]);

  const best = new Map<number, (typeof tags)[number]>();
  const candidateCount = new Map<number, number>();
  for (const t of sortTags(tags)) {
    if (!best.has(t.image_id)) best.set(t.image_id, t);
    candidateCount.set(t.image_id, (candidateCount.get(t.image_id) ?? 0) + 1);
  }
  const bestScans = [...best.values()]
    .map((t) => (t.digest ? scansByDigest.get(scanKey(t.image_id, t.digest)) : undefined))
    .filter((s) => s !== undefined);
  const summaries = await summariesForScans(db, bestScans, runningDigestsByImage(live));

  let rows: OverviewRow[] = images.map((img) => {
    const ws = byImage.get(img.id) ?? [];
    const c = counts.get(img.id) ?? { critical: 0, high: 0, medium: 0 };
    const t = best.get(img.id);
    const scan = t?.digest ? scansByDigest.get(scanKey(img.id, t.digest)) : undefined;
    return {
      imageId: img.id,
      registry: img.registry,
      repository: img.repository,
      tags: [...new Set(ws.map((w) => w.tag))].sort((a, b) => (a ?? "").localeCompare(b ?? "")),
      workloads: ws.length,
      namespaces: [...new Set(ws.map((w) => w.namespace))].sort(),
      digests: new Set(ws.map((w) => w.digest_id).filter((d) => d != null)).size,
      ...c,
      candidateCount: candidateCount.get(img.id) ?? 0,
      tagCheck: tagCheckOf(img, ws),
      candidate: t
        ? {
            tag: t.tag,
            reason: t.reason,
            hasDigest: !!t.digest,
            scan: scan ? { id: scan.id, status: scan.status, diff: summaries.get(scan.id) ?? null } : null,
          }
        : null,
    };
  });

  if (opts.minSeverity) {
    const min = opts.minSeverity;
    rows = rows.filter((r) => r.critical > 0 || (min !== "CRITICAL" && (r.high > 0 || (min === "MEDIUM" && r.medium > 0))));
  }
  if (opts.hasCandidate) rows = rows.filter((r) => r.candidate);
  rows.sort(comparator(opts.sort, opts.dir));

  return { rows, totals: totalsOf(rows), namespaces, lastReportSync: lastReportSync ?? null };
}

const imageName = (r: OverviewRow) => `${r.registry}/${r.repository}`;
const worstFirst = (a: OverviewRow, b: OverviewRow) =>
  b.critical - a.critical || b.high - a.high || b.medium - a.medium || imageName(a).localeCompare(imageName(b));

function comparator(sort: SortKey | undefined, dir: "asc" | "desc" | undefined) {
  const base = (a: OverviewRow, b: OverviewRow): number => {
    switch (sort) {
      case "image":
        return imageName(a).localeCompare(imageName(b));
      case "workloads":
        return a.workloads - b.workloads || -worstFirst(a, b);
      case "critical":
        return a.critical - b.critical || -worstFirst(a, b);
      case "high":
        return a.high - b.high || -worstFirst(a, b);
      case "medium":
        return a.medium - b.medium || -worstFirst(a, b);
      case "candidate": {
        // Descending (the default) puts the most useful first: the scanned candidate that fixes the most.
        const score = (r: OverviewRow) => (r.candidate ? 1 + (r.candidate.scan?.diff ? 1 + r.candidate.scan.diff.fixed : 0) : 0);
        return score(a) - score(b) || -worstFirst(a, b);
      }
      default:
        return -worstFirst(a, b);
    }
  };
  const defaultDir = sort === "image" ? "asc" : "desc";
  const sign = (dir ?? defaultDir) === "asc" ? 1 : -1;
  return (a: OverviewRow, b: OverviewRow) => sign * base(a, b);
}

function tagCheckOf(
  img: { last_tag_sync_at: string | null; tag_sync_error: string | null },
  ws: { tag: string | null }[],
): OverviewRow["tagCheck"] {
  const tags = ws.map((w) => w.tag).filter((t): t is string => t != null);
  return {
    checkedAt: img.last_tag_sync_at,
    error: img.tag_sync_error,
    pinned: ws.length > 0 && tags.length === 0,
    floating: tags.length > 0 && tags.every((t) => parseTag(t).kind !== "version"),
  };
}

function emptyTotals(): Overview["totals"] {
  return { images: 0, workloads: 0, critical: 0, high: 0, medium: 0, withCandidate: 0, candidatesScanned: 0, tagsChecked: 0 };
}

function totalsOf(rows: OverviewRow[]): Overview["totals"] {
  const t = emptyTotals();
  for (const r of rows) {
    t.images++;
    t.workloads += r.workloads;
    t.critical += r.critical;
    t.high += r.high;
    t.medium += r.medium;
    if (r.candidate) t.withCandidate++;
    if (r.candidate?.scan?.status === "done") t.candidatesScanned++;
    if (r.tagCheck.checkedAt) t.tagsChecked++;
  }
  return t;
}
