import { getConfig } from "./lib/config";
import { getDb, migrate } from "./lib/db";
import { pruneSyncRuns, withSyncRun } from "./lib/db/store";
import { errorMessage, log } from "./lib/log";
import { syncReports } from "./lib/k8s/report-sync";
import { syncTags } from "./lib/candidates/tag-sync";
import { runScanQueue } from "./lib/scan/queue";
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
