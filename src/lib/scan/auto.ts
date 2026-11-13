import { liveWorkloads, sortTags } from "../queries/common";
import { getSettings } from "../settings";
import type { WorkerContext } from "../worker-context";
import { queueScan } from "./enqueue";

/** Recorded as `requested_by` on scans this loop queues. */
export const AUTO_REQUESTER = "auto";

/**
 * Queues the scans the Settings page asks for. For each image in use:
 * - its best candidate (the one the Overview shows), when it has a digest;
 * - the build a pod runs, when it is older than its tag.
 *
 * A digest that already has a scan in any state is left alone, so a failed
 * automatic scan is not retried in a loop; Retry on the image page does that.
 * The scan queue still runs them SCAN_CONCURRENCY at a time.
 */
export async function autoScan(ctx: WorkerContext): Promise<Record<string, unknown>> {
  const { db } = ctx;
  const settings = await getSettings(db);
  if (!settings.autoScanBestCandidate && !settings.autoScanRunningBuild) return { idle: true, disabled: true };

  const live = await liveWorkloads(db);
  const imageIds = [...new Set(live.map((w) => w.image_id))];
  if (imageIds.length === 0) return { idle: true };
  const scanned = new Set(
    (await db.selectFrom("scans").select(["image_id", "digest"]).where("image_id", "in", imageIds).execute()).map(
      (s) => `${s.image_id}\u0000${s.digest}`,
    ),
  );
  const want: { imageId: number; tag: string; digest: string }[] = [];

  if (settings.autoScanBestCandidate) {
    const tags = await db.selectFrom("tags").selectAll().where("image_id", "in", imageIds).where("is_candidate", "=", 1).execute();
    const best = new Map<number, (typeof tags)[number]>();
    for (const t of sortTags(tags)) if (!best.has(t.image_id)) best.set(t.image_id, t);
    for (const t of best.values()) if (t.digest) want.push({ imageId: t.image_id, tag: t.tag, digest: t.digest });
  }
  if (settings.autoScanRunningBuild) {
    for (const w of live) if (w.pod_digest) want.push({ imageId: w.image_id, tag: w.tag ?? w.pod_digest, digest: w.pod_digest });
  }

  let queued = 0;
  for (const s of want) {
    if (ctx.signal.aborted) break;
    const key = `${s.imageId}\u0000${s.digest}`;
    if (scanned.has(key)) continue;
    scanned.add(key);
    if ((await queueScan(db, { ...s, requestedBy: AUTO_REQUESTER })).created) queued++;
  }
  return queued ? { queued } : { idle: true };
}
