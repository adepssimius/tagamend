import type { DB } from "../db";
import type { Workload } from "../db/schema";
import { latestScansByDigest, liveWorkloads, runningDigestsByImage, severityRank, worstSeverity } from "./common";

export interface CveFinding {
  digestId: number;
  digest: string;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: string;
}

export interface CveCandidate {
  scanId: number;
  tag: string;
  digest: string;
  /** True when the candidate's scan has no finding with this vuln id. */
  fixes: boolean;
}

export interface CveImage {
  imageId: number;
  registry: string;
  repository: string;
  findings: CveFinding[];
  workloads: Workload[];
  /** Done scans of non-running digests of this image, newest per digest. */
  candidates: CveCandidate[];
}

export interface CvePage {
  vulnId: string;
  title: string | null;
  severity: string | null;
  score: number | null;
  link: string | null;
  /** Images whose running digests contain the vuln, worst severity first. */
  affected: CveImage[];
  /** Scanned candidates that would introduce it into an image that does not run it today. */
  introducedBy: { imageId: number; registry: string; repository: string; scanId: number; tag: string }[];
}

/**
 * Everything about one vuln id. "Fixes" is judged by vuln id alone, across
 * packages: a candidate fixes the CVE when its scan has no finding with that
 * id. (The scan page's diff keys by (vuln_id, package), so a package rename
 * there shows as one fixed and one new.)
 */
export async function getCvePage(db: DB, vulnId: string): Promise<CvePage> {
  const rows = await db
    .selectFrom("vulnerabilities as v")
    .innerJoin("image_digests as d", "d.id", "v.digest_id")
    .innerJoin("images as i", "i.id", "d.image_id")
    .select([
      "v.digest_id",
      "v.package",
      "v.installed_version",
      "v.fixed_version",
      "v.severity",
      "v.score",
      "v.title",
      "v.link",
      "d.digest",
      "d.image_id",
      "i.registry",
      "i.repository",
    ])
    .where("v.vuln_id", "=", vulnId)
    .execute();

  const page: CvePage = { vulnId, title: null, severity: null, score: null, link: null, affected: [], introducedBy: [] };
  if (rows.length === 0) return page;
  for (const r of rows) {
    page.title ??= r.title;
    page.link ??= r.link;
    page.severity = page.severity ? worstSeverity(page.severity, r.severity) : r.severity;
    if (r.score != null) page.score = Math.max(page.score ?? 0, r.score);
  }

  const imageIds = [...new Set(rows.map((r) => r.image_id))];
  const [live, scansByDigest] = await Promise.all([liveWorkloads(db, { imageIds }), latestScansByDigest(db, imageIds)]);
  const running = runningDigestsByImage(live);
  const hasVuln = new Set(rows.map((r) => r.digest_id));

  for (const imageId of imageIds) {
    const runningIds = new Set(running.get(imageId) ?? []);
    const imgRows = rows.filter((r) => r.image_id === imageId);
    const first = imgRows[0]!;
    const findings = imgRows
      .filter((r) => runningIds.has(r.digest_id))
      .map((r) => ({
        digestId: r.digest_id,
        digest: r.digest,
        package: r.package,
        installedVersion: r.installed_version,
        fixedVersion: r.fixed_version,
        severity: r.severity,
      }));
    const candidateScans = [...scansByDigest.values()].filter(
      (s) => s.image_id === imageId && s.status === "done" && s.result_digest_id != null && !runningIds.has(s.result_digest_id),
    );
    if (findings.length) {
      page.affected.push({
        imageId,
        registry: first.registry,
        repository: first.repository,
        findings,
        workloads: live.filter((w) => w.image_id === imageId && w.digest_id != null && hasVuln.has(w.digest_id)),
        candidates: candidateScans
          .map((s) => ({ scanId: s.id, tag: s.tag, digest: s.digest, fixes: !hasVuln.has(s.result_digest_id!) }))
          .sort((a, b) => Number(b.fixes) - Number(a.fixes) || b.scanId - a.scanId),
      });
    } else {
      for (const s of candidateScans.filter((s) => hasVuln.has(s.result_digest_id!))) {
        page.introducedBy.push({ imageId, registry: first.registry, repository: first.repository, scanId: s.id, tag: s.tag });
      }
    }
  }
  const worst = (img: CveImage) => Math.min(...img.findings.map((f) => severityRank(f.severity)));
  page.affected.sort(
    (a, b) => worst(a) - worst(b) || `${a.registry}/${a.repository}`.localeCompare(`${b.registry}/${b.repository}`),
  );
  return page;
}
