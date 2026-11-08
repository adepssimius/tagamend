import { z } from "zod";
import type { Config } from "../config";
import { now } from "../db";
import type { Scan } from "../db/schema";
import { setKv, storeDigest, withSyncRun } from "../db/store";
import { KV } from "../kv-keys";
import { errorMessage } from "../log";
import { parseTrivyScan } from "../trivy/scan-json";
import type { WorkerContext } from "../worker-context";
import { JobScanRunner } from "./job-runner";
import { LocalScanRunner } from "./local-runner";
import { type RunState, type ScanRunner, shortError } from "./runner";
import { fetchTrivyServerVersion } from "./server-version";

export interface ScanQueueDeps {
  runner: ScanRunner;
  /** Reads the Trivy server's version; omitted in tests that do not care. */
  serverVersion?: () => Promise<string>;
  /** How often to refresh `KV.trivyServerVersion`. */
  serverVersionEveryMs?: number;
}

export type ScanQueueTick = (ctx: WorkerContext) => Promise<Record<string, unknown>>;

/** The runner `SCANNER` selects. */
export async function createRunner(config: Config, signal?: AbortSignal): Promise<ScanRunner> {
  if (config.SCANNER === "local") return new LocalScanRunner(config, { signal });
  // Imported here so that SCANNER=local never loads the Kubernetes client.
  const { getK8s } = await import("../k8s/client");
  const { batch, core } = getK8s();
  return new JobScanRunner(config, { batch, core });
}

/**
 * Builds the scan queue's tick. Each tick:
 *
 * 1. On the first tick only, reports the scans left `running` by an earlier
 *    worker; the checks below re-attach to their Jobs by `job_name`.
 * 2. Checks every `running` scan. A finished one is parsed and stored, or
 *    marked failed; one whose Job is gone is marked failed.
 * 3. Starts `queued` scans, oldest first, up to `SCAN_CONCURRENCY`.
 *
 * A tick that finishes or starts something is recorded in `sync_runs`; idle
 * ticks are not.
 */
export function createScanQueue(deps: ScanQueueDeps): ScanQueueTick {
  const { runner } = deps;
  let reconciled = false;
  let versionDueAt = 0;
  let versionFailing = false;

  async function refreshServerVersion(ctx: WorkerContext) {
    if (!deps.serverVersion || Date.now() < versionDueAt) return;
    versionDueAt = Date.now() + (deps.serverVersionEveryMs ?? 10 * 60_000);
    try {
      const v = await deps.serverVersion();
      await setKv(ctx.db, KV.trivyServerVersion, v);
      versionFailing = false;
    } catch (e) {
      // Logged once per run of failures: the server may simply be down.
      if (!versionFailing) ctx.log.warn("trivy server version unavailable", { error: errorMessage(e) });
      versionFailing = true;
    }
  }

  async function check(ctx: WorkerContext, scan: Scan): Promise<RunState> {
    if (!scan.job_name) return { state: "failed", error: "the worker stopped before the scan was started" };
    try {
      const s = await runner.check(scan.job_name);
      if (s.state !== "missing") return s;
      return {
        state: "failed",
        error:
          runner.kind === "job"
            ? `scan Job ${scan.job_name} no longer exists`
            : "the worker restarted while the local scan was running",
      };
    } catch (e) {
      // A transient API error: look again next tick.
      ctx.log.warn("scan check failed", { scan: scan.id, job: scan.job_name, error: errorMessage(e) });
      return { state: "running" };
    }
  }

  async function finish(ctx: WorkerContext, scan: Scan, s: Extract<RunState, { state: "succeeded" | "failed" }>) {
    const { db, config } = ctx;
    if (s.state === "failed") return markFailed(ctx, scan.id, s.error);
    let digestId: number;
    try {
      const parsed = parseTrivyScan(s.output, scan.digest);
      // An operator report of the same digest wins: once a candidate runs, its
      // report is the authoritative one, and a scan must not overwrite it.
      const operator = await db
        .selectFrom("image_digests")
        .select("id")
        .where("image_id", "=", scan.image_id)
        .where("digest", "=", scan.digest)
        .where("source", "=", "operator")
        .executeTakeFirst();
      digestId = operator
        ? operator.id
        : (await storeDigest(db, scan.image_id, "candidate", parsed, config.SEVERITIES)).digestId;
      ctx.log.info("scan done", { scan: scan.id, findings: parsed.findings.length, digestId, reusedOperator: !!operator });
    } catch (e) {
      const msg = e instanceof z.ZodError ? `invalid scan output: ${z.prettifyError(e)}` : errorMessage(e);
      return markFailed(ctx, scan.id, msg);
    }
    await db
      .updateTable("scans")
      .set({ status: "done", finished_at: now(), result_digest_id: digestId, error: null })
      .where("id", "=", scan.id)
      .execute();
    return "done" as const;
  }

  async function markFailed(ctx: WorkerContext, id: number, error: string) {
    ctx.log.warn("scan failed", { scan: id, error });
    await ctx.db
      .updateTable("scans")
      .set({ status: "failed", finished_at: now(), error: shortError(error) })
      .where("id", "=", id)
      .execute();
    return "failed" as const;
  }

  async function start(ctx: WorkerContext, scan: Scan): Promise<"started" | "failed" | "skipped"> {
    const { db } = ctx;
    const image = await db
      .selectFrom("images")
      .select(["registry", "repository"])
      .where("id", "=", scan.image_id)
      .executeTakeFirst();
    if (!image) return markFailed(ctx, scan.id, "the image is no longer in the database");
    // Claim the row first, so a crash after the Job exists leaves a `running`
    // scan that the next worker resolves, never a second Job for one scan.
    const claimed = await db
      .updateTable("scans")
      .set({ status: "running", started_at: now(), error: null })
      .where("id", "=", scan.id)
      .where("status", "=", "queued")
      .executeTakeFirst();
    if (Number(claimed.numUpdatedRows) === 0) return "skipped";
    try {
      const handle = await runner.start({
        scanId: scan.id,
        registry: image.registry,
        repository: image.repository,
        digest: scan.digest,
      });
      await db.updateTable("scans").set({ job_name: handle }).where("id", "=", scan.id).execute();
      ctx.log.info("scan started", { scan: scan.id, job: handle, image: `${image.registry}/${image.repository}` });
      return "started";
    } catch (e) {
      return markFailed(ctx, scan.id, `could not start the scan: ${errorMessage(e)}`);
    }
  }

  return async function tick(ctx: WorkerContext) {
    const { db, config, signal } = ctx;
    if (signal.aborted) return { skipped: "stopping" };
    await refreshServerVersion(ctx);

    const running = await db.selectFrom("scans").selectAll().where("status", "=", "running").orderBy("id").execute();
    if (!reconciled) {
      reconciled = true;
      if (running.length) {
        ctx.log.info("re-attaching running scans", { scanner: runner.kind, scans: running.map((s) => s.job_name) });
      }
    }

    const finished: { scan: Scan; state: Extract<RunState, { state: "succeeded" | "failed" }> }[] = [];
    for (const scan of running) {
      if (signal.aborted) return { skipped: "stopping" };
      const state = await check(ctx, scan);
      if (state.state === "succeeded" || state.state === "failed") finished.push({ scan, state });
    }

    const slots = config.SCAN_CONCURRENCY - (running.length - finished.length);
    const queued =
      slots > 0
        ? await db
            .selectFrom("scans")
            .selectAll()
            .where("status", "=", "queued")
            .orderBy("requested_at")
            .orderBy("id")
            .limit(slots)
            .execute()
        : [];

    if (!finished.length && !queued.length) return { idle: true, running: running.length };
    // A scan killed by shutdown has not failed; leave it for the next worker.
    if (signal.aborted) return { skipped: "stopping" };

    return (
      (await withSyncRun(db, "scan_queue", async () => {
        const counts = { done: 0, failed: 0, started: 0, running: running.length - finished.length };
        for (const { scan, state } of finished) counts[await finish(ctx, scan, state)]++;
        for (const scan of queued) {
          if (signal.aborted) break;
          const r = await start(ctx, scan);
          if (r === "started") (counts.started++, counts.running++);
          else if (r === "failed") counts.failed++;
        }
        return counts;
      })) ?? {}
    );
  };
}

let defaultTick: ScanQueueTick | undefined;

/**
 * Called by the worker every 5 seconds. Starts queued scans up to
 * SCAN_CONCURRENCY, checks running ones, and stores finished results.
 */
export async function runScanQueue(ctx: WorkerContext): Promise<Record<string, unknown>> {
  defaultTick ??= createScanQueue({
    runner: await createRunner(ctx.config, ctx.signal),
    serverVersion: () => fetchTrivyServerVersion(ctx.config.TRIVY_SERVER_URL, { signal: ctx.signal }),
  });
  return defaultTick(ctx);
}
