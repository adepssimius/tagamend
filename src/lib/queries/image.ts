import type { DB } from "../db";
import type { Image, ImageDigest, Scan, Tag, Vulnerability, Workload } from "../db/schema";
import {
  bySeverity,
  type DiffCounts,
  latestScansByDigest,
  runningDigestsByImage,
  scanKey,
  sortTags,
  summariesForScans,
  vulnsForDigests,
} from "./common";

export interface ImageVulnRow extends Vulnerability {
  /** The running digests this finding appears in. */
  digestIds: number[];
}

export interface ImageTagRow extends Tag {
  scan: Scan | null;
  diff: DiffCounts | null;
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

  const [runningDigests, rawVulns, tags, scansByDigest, recent] = await Promise.all([
    runningIds.length
      ? db.selectFrom("image_digests").selectAll().where("id", "in", runningIds).orderBy("id").execute()
      : Promise.resolve([]),
    vulnsForDigests(db, runningIds),
    db.selectFrom("tags").selectAll().where("image_id", "=", imageId).execute(),
    latestScansByDigest(db, [imageId]),
    db.selectFrom("scans").selectAll().where("image_id", "=", imageId).orderBy("id", "desc").limit(20).execute(),
  ]);

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
        return { ...t, scan, diff: scan ? (summaries.get(scan.id) ?? null) : null };
      }),
    ),
    pinnedByDigest: live.length > 0 && live.every((w) => w.tag == null),
    recentScans: recent.map((s) => ({ ...s, diff: summaries.get(s.id) ?? null })),
  };
}
