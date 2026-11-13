import type { DB } from "../db";
import type { Chart, ChartCandidate, Scan, Vulnerability } from "../db/schema";
import { type CveCounts, cveCounts, liveWorkloads, unionVulns, vulnsForDigests } from "../queries/common";
import { kevFor } from "../queries/kev";
import { type Diff, diffVulnerabilities } from "../trivy/diff";
import type { ChartImageChange } from "./types";

export interface ChartChangeDiff {
  change: ChartImageChange;
  /** The image's row in `images`, when it exists (needed to scan it). */
  imageId: number | null;
  /** Digests running now for this image in the HelmRelease's workloads. */
  runningDigestIds: number[];
  /** The newest scan of change.to.digest, if any. */
  scan: Scan | null;
  running: CveCounts | null;
  candidate: CveCounts | null;
  diff: Diff<Vulnerability> | null;
}

/**
 * For each image a chart candidate changes: what runs now, what the candidate
 * would run, and the CVE diff once the candidate's image is scanned. "Running"
 * is the live workloads of the HelmRelease's namespace whose kind and name
 * match the rendered object and whose image is the same repository.
 */
export async function chartCandidateDiff(db: DB, chart: Chart, candidate: ChartCandidate): Promise<ChartChangeDiff[]> {
  const changes = candidate.changes ? (JSON.parse(candidate.changes) as ChartImageChange[]) : [];
  if (changes.length === 0) return [];
  const live = await liveWorkloads(db, { namespace: chart.namespace });
  const images = await db.selectFrom("images").selectAll().execute();
  const imageIdOf = (registry: string, repository: string) =>
    images.find((i) => i.registry === registry && i.repository === repository)?.id ?? null;

  const out: ChartChangeDiff[] = [];
  for (const change of changes) {
    const ref = change.to ?? change.from!;
    const imageId = imageIdOf(ref.registry, ref.repository);
    const runningDigestIds = [
      ...new Set(
        live
          .filter((w) => w.kind === change.kind && w.name === change.name && w.image_id === imageId && w.digest_id != null)
          .map((w) => w.digest_id!),
      ),
    ];
    let scan: Scan | null = null;
    if (imageId != null && change.to?.digest) {
      scan =
        (await db
          .selectFrom("scans")
          .selectAll()
          .where("image_id", "=", imageId)
          .where("digest", "=", change.to.digest)
          .orderBy("id", "desc")
          .executeTakeFirst()) ?? null;
    }
    const resultId = scan?.status === "done" ? scan.result_digest_id : null;
    const vulns = await vulnsForDigests(db, [...runningDigestIds, ...(resultId != null ? [resultId] : [])]);
    const kev = new Set((await kevFor(db, vulns.map((v) => v.vuln_id))).keys());
    const runningVulns = unionVulns(vulns.filter((v) => runningDigestIds.includes(v.digest_id)));
    const candidateVulns = resultId != null ? vulns.filter((v) => v.digest_id === resultId) : null;
    out.push({
      change,
      imageId,
      runningDigestIds,
      scan,
      running: runningDigestIds.length ? cveCounts(runningVulns, kev) : null,
      candidate: candidateVulns ? cveCounts(candidateVulns, kev) : null,
      diff: candidateVulns && runningDigestIds.length ? diffVulnerabilities(runningVulns, candidateVulns) : null,
    });
  }
  return out;
}
