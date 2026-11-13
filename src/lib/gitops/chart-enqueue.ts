import type { DB } from "../db";
import type { ChartPullRequest } from "../db/schema";

/**
 * Queues a PR that bumps a HelmRelease's chart to a candidate version.
 * Called by the web process; the worker's PR queue opens it. A request for the
 * same candidate that is queued, running or opened (and still open on GitHub)
 * is returned instead of adding another. Implemented by the chart PR milestone.
 */
export async function queueChartPullRequest(
  _db: DB,
  _req: { candidateId: number; requestedBy: string; updatePins: boolean },
): Promise<{ pr: ChartPullRequest; created: boolean }> {
  throw new Error("chart PRs are not implemented yet");
}
