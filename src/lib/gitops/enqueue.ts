import { type DB, now } from "../db";
import type { PullRequest } from "../db/schema";

/**
 * Queues a GitOps PR for a scanned candidate. Called by the web process; the
 * worker opens it. A request for the same image and tag that is queued,
 * running or opened is returned instead of adding another. A failed one can be
 * retried.
 */
export async function queuePullRequest(
  db: DB,
  req: { scanId: number; requestedBy: string; workloads?: string[] | null },
): Promise<{ pr: PullRequest; created: boolean }> {
  const scan = await db.selectFrom("scans").selectAll().where("id", "=", req.scanId).executeTakeFirst();
  if (!scan) throw new Error(`scan ${req.scanId} does not exist`);
  if (scan.status !== "done") throw new Error(`scan ${req.scanId} is ${scan.status}, not done`);
  // Null means every workload; a subset is stored sorted so equal choices compare equal.
  const workloads = req.workloads?.length ? JSON.stringify([...new Set(req.workloads)].sort()) : null;
  const existing = await db
    .selectFrom("pull_requests")
    .selectAll()
    .where("image_id", "=", scan.image_id)
    .where("to_tag", "=", scan.tag)
    .where("status", "in", ["queued", "running", "opened"])
    .where((eb) => (workloads ? eb("workloads", "=", workloads) : eb("workloads", "is", null)))
    // A merged or closed PR does not block a new one.
    .where((eb) => eb.or([eb("pr_state", "is", null), eb("pr_state", "in", ["open", "draft"])]))
    .orderBy("id", "desc")
    .executeTakeFirst();
  if (existing) return { pr: existing, created: false };
  const pr = await db
    .insertInto("pull_requests")
    .values({
      image_id: scan.image_id,
      scan_id: scan.id,
      to_tag: scan.tag,
      to_digest: scan.digest,
      status: "queued",
      requested_by: req.requestedBy,
      requested_at: now(),
      started_at: null,
      finished_at: null,
      branch: null,
      pr_number: null,
      pr_url: null,
      workloads,
      pr_state: null,
      pr_state_checked_at: null,
      edits: null,
      skipped: null,
      error: null,
    })
    .returningAll()
    .executeTakeFirstOrThrow();
  return { pr, created: true };
}
