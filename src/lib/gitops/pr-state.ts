import type { DB } from "../db";
import { errorMessage, log } from "../log";
import { type GitHub, gitHubClient } from "./github";

/** A state read this recently is reused instead of asking GitHub again. */
export const PR_STATE_FRESH_MS = 30_000;
/** A page never waits longer than this on GitHub; it shows the stored state instead. */
const TIMEOUT_MS = 3_000;

/**
 * Reads back from GitHub the state of opened PRs that are still open or a
 * draft, so a page shows merged or closed as soon as it is reloaded. Called by
 * pages on view, not by a background loop. A merged or closed PR is final and
 * never checked again; a state checked in the last PR_STATE_FRESH_MS is reused.
 *
 * Uses a read-only token (GITHUB_READ_TOKEN). Failures are logged and the
 * stored state stands, so GitHub being slow or down never breaks a page.
 */
export async function refreshPrStates(
  db: DB,
  opts: { repo: string | undefined; token: string | undefined; imageId?: number; github?: GitHub; nowMs?: () => number },
): Promise<number> {
  if (!opts.repo || (!opts.token && !opts.github)) return 0;
  const nowMs = opts.nowMs ?? Date.now;
  const cutoff = new Date(nowMs() - PR_STATE_FRESH_MS).toISOString();
  let q = db
    .selectFrom("pull_requests")
    .select(["id", "pr_number", "pr_state"])
    .where("status", "=", "opened")
    .where("pr_number", "is not", null)
    .where((eb) => eb.or([eb("pr_state", "is", null), eb("pr_state", "in", ["open", "draft"])]))
    .where((eb) => eb.or([eb("pr_state_checked_at", "is", null), eb("pr_state_checked_at", "<", cutoff)]));
  if (opts.imageId !== undefined) q = q.where("image_id", "=", opts.imageId);
  const due = await q.limit(20).execute();
  if (due.length === 0) return 0;

  const github = opts.github ?? gitHubClient(opts.repo, opts.token!, (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) }));
  const results = await Promise.allSettled(due.map((pr) => github.prState(pr.pr_number!)));
  let changed = 0;
  const at = new Date(nowMs()).toISOString();
  for (const [i, r] of results.entries()) {
    const pr = due[i]!;
    if (r.status === "rejected") {
      log.warn("pr state check failed", { pr: pr.id, error: errorMessage(r.reason) });
      continue;
    }
    if (r.value !== pr.pr_state) changed++;
    await db.updateTable("pull_requests").set({ pr_state: r.value, pr_state_checked_at: at }).where("id", "=", pr.id).execute();
  }
  return changed;
}
