import { getConfig } from "./lib/config";
import { getDb, migrate } from "./lib/db";
import { pruneSyncRuns, withSyncRun } from "./lib/db/store";
import { errorMessage, log } from "./lib/log";
import { syncReports } from "./lib/k8s/report-sync";
import { syncTags } from "./lib/candidates/tag-sync";
import { runScanQueue } from "./lib/scan/queue";
import { runPrQueue } from "./lib/gitops/queue";
import { syncKev } from "./lib/kev/sync";
import { autoScan } from "./lib/scan/auto";
import { syncExposure } from "./lib/exposure/sync";
import { syncCharts } from "./lib/charts/sync";
import type { SyncName } from "./lib/db/schema";
import type { WorkerContext } from "./lib/worker-context";

const config = getConfig();
const db = await getDb();
await migrate(db);

const abort = new AbortController();
const ctx: WorkerContext = { db, config, log, signal: abort.signal };

/**
 * Runs `fn` now and then every `everyMs`, never overlapping itself. A failure
 * is logged and recorded in sync_runs; the loop carries on.
 */
function loop(name: SyncName, everyMs: number, fn: (c: WorkerContext) => Promise<Record<string, unknown>>, record = true) {
  let timer: NodeJS.Timeout | undefined;
  let running: Promise<void> = Promise.resolve();
  const tick = async () => {
    if (abort.signal.aborted) return;
    const started = Date.now();
    try {
      const detail = record ? await withSyncRun(db, name, () => fn(ctx)) : await fn(ctx);
      // An idle queue tick happens every few seconds and says nothing.
      const write = detail?.idle ? log.debug : log.info;
      write(`${name} done`, { ms: Date.now() - started, ...detail });
    } catch (e) {
      log.error(`${name} failed`, { ms: Date.now() - started, error: errorMessage(e) });
    }
    if (!abort.signal.aborted) timer = setTimeout(() => (running = tick()), everyMs);
  };
  running = tick();
  return { stop: async () => (clearTimeout(timer), running) };
}

const loops = [
  loop("report_sync", config.REPORT_SYNC_INTERVAL, syncReports),
  // Tag sync decides per image what is due, so it ticks often and does little.
  loop("tag_sync", 60_000, syncTags),
  // The queue ticks every few seconds; recording each idle tick would flood
  // sync_runs, so it records its own runs when it does work.
  loop("scan_queue", 5_000, runScanQueue, false),
  // Records its own runs, like the scan queue.
  loop("pr_queue", 5_000, (c) => runPrQueue(c), false),
  // CISA updates the catalog a few times a week.
  loop("kev_sync", 6 * 3_600_000, (c) => syncKev(c)),
  // Off unless turned on in Settings; when on, finds candidates within a minute of tag discovery.
  loop("auto_scan", 60_000, autoScan, false),
  // Ingresses and Services change rarely; settings changes show within this interval.
  loop("exposure_sync", 5 * 60_000, (c) => syncExposure(c)),
  // Picks the HelmReleases that are due, a few per tick, like tag discovery.
  loop("chart_sync", 60_000, syncCharts, false),
];
const pruner = setInterval(() => pruneSyncRuns(db).catch((e) => log.warn("prune failed", { error: errorMessage(e) })), 3_600_000);

log.info("worker started", { scanner: config.SCANNER, severities: config.SEVERITIES });

for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.once(sig, async () => {
    log.info("worker stopping", { signal: sig });
    abort.abort();
    clearInterval(pruner);
    await Promise.all(loops.map((l) => l.stop()));
    await db.destroy();
    process.exit(0);
  });
}
