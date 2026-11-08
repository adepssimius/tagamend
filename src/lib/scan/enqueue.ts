import { type DB, now } from "../db";
import type { Scan } from "../db/schema";

/**
 * Queues a candidate scan. Called by the web process. If a scan of the same
 * digest is already queued, running or done, that scan is returned instead of
 * adding another.
 */
export async function queueScan(
  db: DB,
  req: { imageId: number; tag: string; digest: string; requestedBy: string },
): Promise<{ scan: Scan; created: boolean }> {
  const existing = await db
    .selectFrom("scans")
    .selectAll()
    .where("image_id", "=", req.imageId)
    .where("digest", "=", req.digest)
    .where("status", "in", ["queued", "running", "done"])
    .orderBy("id", "desc")
    .executeTakeFirst();
  if (existing) return { scan: existing, created: false };
  const scan = await db
    .insertInto("scans")
    .values({
      image_id: req.imageId,
      tag: req.tag,
      digest: req.digest,
      status: "queued",
      requested_by: req.requestedBy,
      requested_at: now(),
      started_at: null,
      finished_at: null,
      job_name: null,
      error: null,
      result_digest_id: null,
    })
    .returningAll()
    .executeTakeFirstOrThrow();
  return { scan, created: true };
}
