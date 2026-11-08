import type { DB } from "../db";
import type { Image, ImageDigest, Scan, Vulnerability } from "../db/schema";
import { type Diff, diffVulnerabilities } from "../trivy/diff";
import { bySeverity, liveWorkloads, runningDigestsByImage, unionVulns, vulnsForDigests } from "./common";

export interface ScanPage {
  scan: Scan;
  image: Image;
  resultDigest: ImageDigest | null;
  /** Every digest the image runs now. */
  runningDigests: ImageDigest[];
  /** The running digests the diff compares against: all of them, or the one chosen. */
  comparedWith: ImageDigest[];
  diff: Diff<Vulnerability> | null;
}

/**
 * The full diff of a candidate scan against the running image. With several
 * running digests, the default compares against their union (see unionVulns);
 * `runningDigestId` narrows it to one.
 */
export async function getScanPage(db: DB, scanId: number, runningDigestId?: number): Promise<ScanPage | null> {
  const scan = await db.selectFrom("scans").selectAll().where("id", "=", scanId).executeTakeFirst();
  if (!scan) return null;
  const image = await db.selectFrom("images").selectAll().where("id", "=", scan.image_id).executeTakeFirstOrThrow();
  const runningIds = runningDigestsByImage(await liveWorkloads(db, { imageIds: [image.id] })).get(image.id) ?? [];
  const digestIds = [...runningIds, ...(scan.result_digest_id != null ? [scan.result_digest_id] : [])];
  const digests = digestIds.length
    ? await db.selectFrom("image_digests").selectAll().where("id", "in", digestIds).execute()
    : [];
  const runningDigests = digests.filter((d) => runningIds.includes(d.id));
  const resultDigest = digests.find((d) => d.id === scan.result_digest_id) ?? null;
  const comparedWith =
    runningDigestId != null && runningIds.includes(runningDigestId)
      ? runningDigests.filter((d) => d.id === runningDigestId)
      : runningDigests;

  let diff: Diff<Vulnerability> | null = null;
  if (scan.status === "done" && resultDigest && comparedWith.length) {
    const vulns = await vulnsForDigests(db, [...comparedWith.map((d) => d.id), resultDigest.id]);
    const compared = new Set(comparedWith.map((d) => d.id));
    const running = unionVulns(vulns.filter((v) => compared.has(v.digest_id)));
    const candidate = vulns.filter((v) => v.digest_id === resultDigest.id);
    const d = diffVulnerabilities(running, candidate);
    diff = {
      fixed: d.fixed.sort(bySeverity),
      stillPresent: d.stillPresent.sort(
        (a, b) => Number(b.fixAvailableUpstream) - Number(a.fixAvailableUpstream) || bySeverity(a.running, b.running),
      ),
      introduced: d.introduced.sort(bySeverity),
    };
  }
  return { scan, image, resultDigest, runningDigests, comparedWith, diff };
}
