import type { WorkerContext } from "../worker-context";

/**
 * Chart upgrades. Called every minute. Finds Flux HelmReleases, lists newer
 * chart versions, renders each with the HelmRelease's values, and records the
 * images each candidate changes. Implemented in the chart worker milestone.
 */
export async function syncCharts(_ctx: WorkerContext): Promise<Record<string, unknown>> {
  return { idle: true, skipped: "not implemented" };
}
