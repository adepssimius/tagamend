import type { DB } from "../db";
import type { Image, ImageDigest, PullRequest, Scan, Tag, Vulnerability, Workload } from "../db/schema";
import {
  bySeverity,
  type DiffCounts,
  latestScansByDigest,
  runningDigestsByImage,
  scanKey,
  sortTags,
  summariesForScans,
  vulnsForDigests,
  type CveCounts,
  cveCounts,
} from "./common";

export interface ImageVulnRow extends Vulnerability {
  /** The running digests this finding appears in. */
  digestIds: number[];
}

export interface ImageTagRow extends Tag {
  scan: Scan | null;
  diff: DiffCounts | null;
  /** The newest GitOps PR request for this tag. */
  pr: PullRequest | null;
  /** CVE counts of the scanned candidate, counted like `runningCounts`. Null until scanned. */
  counts: CveCounts | null;
}

export interface ImagePage {
  image: Image;
  /** Live first, then gone. */
  workloads: Workload[];
  runningDigests: ImageDigest[];
  vulns: ImageVulnRow[];
  /** Distinct CVE ids among `vulns`. */
  cveCount: number;
  tags: ImageTagRow[];
  /** Every live workload runs the image by digest, with no tag. */
  pinnedByDigest: boolean;
  /** CVEs across the running digests: each CVE once, at its worst severity. */
  runningCounts: CveCounts;
  /**
   * Pods on an older build than their report scanned: the tag moved after they
   * started. `scan` is the newest scan of that build, if any.
   */
  staleBuilds: { tag: string | null; podDigest: string; reportDigest: string | null; scanned: boolean; scan: Scan | null }[];
  recentScans: (Scan & { diff: DiffCounts | null })[];
}

export async function getImagePage(db: DB, imageId: number): Promise<ImagePage | null> {
  const image = await db.selectFrom("images").selectAll().where("id", "=", imageId).executeTakeFirst();
  if (!image) return null;

  const workloads = await db
    .selectFrom("workloads")
    .selectAll()
    .where("image_id", "=", imageId)
    .orderBy("namespace")
    .orderBy("name")
    .orderBy("container")
    .execute();
  workloads.sort((a, b) => Number(a.gone_at != null) - Number(b.gone_at != null));
  const live = workloads.filter((w) => w.gone_at == null);
  const running = runningDigestsByImage(live);
  const runningIds = running.get(imageId) ?? [];

  const [runningDigests, rawVulns, tags, scansByDigest, recent, prs] = await Promise.all([
    runningIds.length
      ? db.selectFrom("image_digests").selectAll().where("id", "in", runningIds).orderBy("id").execute()
      : Promise.resolve([]),
    vulnsForDigests(db, runningIds),
    db.selectFrom("tags").selectAll().where("image_id", "=", imageId).execute(),
    latestScansByDigest(db, [imageId]),
    db.selectFrom("scans").selectAll().where("image_id", "=", imageId).orderBy("id", "desc").limit(20).execute(),
    db.selectFrom("pull_requests").selectAll().where("image_id", "=", imageId).orderBy("id", "desc").execute(),
  ]);
  const prByTag = new Map<string, PullRequest>();
  for (const p of prs) if (!prByTag.has(p.to_tag)) prByTag.set(p.to_tag, p);

  // One row per (vuln_id, package, installed_version, fixed_version) across the running digests.
  const grouped = new Map<string, ImageVulnRow>();
  for (const v of rawVulns) {
    const k = [v.vuln_id, v.package, v.installed_version, v.fixed_version ?? ""].join("\u0000");
    const cur = grouped.get(k);
    if (cur) cur.digestIds.push(v.digest_id);
    else grouped.set(k, { ...v, digestIds: [v.digest_id] });
  }
  const vulns = [...grouped.values()].sort(bySeverity);

  const tagScans = tags.map((t) => (t.digest ? (scansByDigest.get(scanKey(imageId, t.digest)) ?? null) : null));
  const resultIds = [...new Set(tagScans.flatMap((s) => (s?.status === "done" && s.result_digest_id != null ? [s.result_digest_id] : [])))];
  const resultVulns = await vulnsForDigests(db, resultIds);
  const countsByDigest = new Map(resultIds.map((id) => [id, cveCounts(resultVulns.filter((v) => v.digest_id === id))]));
  const summaries = await summariesForScans(
    db,
    [...tagScans.filter((s) => s !== null), ...recent],
    running,
  );

  return {
    image,
    workloads,
    runningDigests,
    vulns,
    cveCount: new Set(vulns.map((v) => v.vuln_id)).size,
    tags: sortTags(
      tags.map((t, i) => {
        const scan = tagScans[i] ?? null;
        return {
          ...t,
          scan,
          diff: scan ? (summaries.get(scan.id) ?? null) : null,
          pr: prByTag.get(t.tag) ?? null,
          counts: scan?.status === "done" && scan.result_digest_id != null ? (countsByDigest.get(scan.result_digest_id) ?? null) : null,
        };
      }),
    ),
    pinnedByDigest: live.length > 0 && live.every((w) => w.tag == null),
    runningCounts: cveCounts(rawVulns),
    staleBuilds: [
      ...new Map(
        live
          .filter((w) => w.pod_digest)
          .map((w) => [
            w.pod_digest!,
            {
              tag: w.tag,
              podDigest: w.pod_digest!,
              reportDigest: w.report_digest,
              scanned: runningDigests.some((d) => d.digest === w.pod_digest),
              scan: scansByDigest.get(scanKey(imageId, w.pod_digest!)) ?? null,
            },
          ]),
      ).values(),
    ],
    recentScans: recent.map((s) => ({ ...s, diff: summaries.get(s.id) ?? null })),
  };
}
