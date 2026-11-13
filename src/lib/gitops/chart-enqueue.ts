import { type DB, now } from "../db";
import type { ChartPullRequest } from "../db/schema";

/**
 * Queues a PR that bumps a HelmRelease's chart to a candidate version.
 * Called by the web process; the worker's PR queue opens it. A request for the
 * same candidate that is queued, running or opened (and still open on GitHub)
 * is returned instead of adding another. A failed one can be retried, and a
 * merged or closed one does not block a new one.
 */
export async function queueChartPullRequest(
  db: DB,
  req: { candidateId: number; requestedBy: string; updatePins: boolean },
): Promise<{ pr: ChartPullRequest; created: boolean }> {
  const candidate = await db.selectFrom("chart_candidates").selectAll().where("id", "=", req.candidateId).executeTakeFirst();
  if (!candidate) throw new Error(`chart candidate ${req.candidateId} does not exist`);
  const chart = await db.selectFrom("charts").selectAll().where("id", "=", candidate.chart_id).executeTakeFirst();
  if (!chart) throw new Error(`chart ${candidate.chart_id} does not exist`);
  if (chart.gone_at) throw new Error(`HelmRelease ${chart.namespace}/${chart.name} no longer exists`);
  const updatePins = req.updatePins ? 1 : 0;
  const existing = await db
    .selectFrom("chart_pull_requests")
    .selectAll()
    .where("candidate_id", "=", candidate.id)
    .where("update_pins", "=", updatePins)
    .where("status", "in", ["queued", "running", "opened"])
    .where((eb) => eb.or([eb("pr_state", "is", null), eb("pr_state", "in", ["open", "draft"])]))
    .orderBy("id", "desc")
    .executeTakeFirst();
  if (existing) return { pr: existing, created: false };
  const pr = await db
    .insertInto("chart_pull_requests")
    .values({
      chart_id: chart.id,
      candidate_id: candidate.id,
      to_version: candidate.version,
      update_pins: updatePins,
      status: "queued",
      requested_by: req.requestedBy,
      requested_at: now(),
      started_at: null,
      finished_at: null,
      branch: null,
      pr_number: null,
      pr_url: null,
      pr_state: null,
      pr_state_checked_at: null,
      edits: null,
      error: null,
    })
    .returningAll()
    .executeTakeFirstOrThrow();
  return { pr, created: true };
}
