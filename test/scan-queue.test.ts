import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getConfig } from "@/lib/config";
import type { DB } from "@/lib/db";
import { getKv, storeDigest, upsertImage } from "@/lib/db/store";
import { KV } from "@/lib/kv-keys";
import { log } from "@/lib/log";
import { queueScan } from "@/lib/scan/enqueue";
import { createScanQueue } from "@/lib/scan/queue";
import type { RunState, ScanRequest, ScanRunner } from "@/lib/scan/runner";
import type { WorkerContext } from "@/lib/worker-context";
import { freshDb, testDatabases } from "./helpers";

const output = readFileSync(path.join(import.meta.dirname, "fixtures/trivy/alpine-3.20.10.json"), "utf8");
const digest = (c: string) => `sha256:${c.repeat(64)}`;

class FakeRunner implements ScanRunner {
  readonly kind: "job" | "local" = "job";
  started: ScanRequest[] = [];
  states = new Map<string, RunState>();
  startError?: Error;
  async start(req: ScanRequest) {
    if (this.startError) throw this.startError;
    this.started.push(req);
    const handle = `job-${req.scanId}`;
    this.states.set(handle, { state: "running" });
    return handle;
  }
  async check(handle: string): Promise<RunState> {
    return this.states.get(handle) ?? { state: "missing" };
  }
}

for (const { name, url } of testDatabases()) {
  describe(`scan queue (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    const ctxFor = (env: Record<string, string> = {}, signal = new AbortController().signal): WorkerContext => ({
      db,
      config: getConfig({ DATABASE_URL: ":memory:", ...env }),
      log: { ...log, info: () => {}, warn: () => {} },
      signal,
    });
    const scanRow = (id: number) => db.selectFrom("scans").selectAll().where("id", "=", id).executeTakeFirstOrThrow();
    const runs = () => db.selectFrom("sync_runs").selectAll().where("name", "=", "scan_queue").orderBy("id").execute();
    async function setup() {
      db = await freshDb(url);
      const imageId = await upsertImage(db, "index.docker.io", "library/alpine");
      const q = (c: string) => queueScan(db, { imageId, tag: `t-${c}`, digest: digest(c), requestedBy: "me" });
      return { imageId, q };
    }

    it("runs scans oldest first up to the concurrency limit and stores results", async () => {
      const { imageId, q } = await setup();
      const a = (await q("a")).scan;
      const b = (await q("b")).scan;
      const runner = new FakeRunner();
      const tick = createScanQueue({ runner });
      const ctx = ctxFor();

      expect(await tick(ctx)).toEqual({ done: 0, failed: 0, started: 1, running: 1 });
      expect(runner.started.map((r) => [r.scanId, r.registry, r.repository, r.digest])).toEqual([
        [a.id, "index.docker.io", "library/alpine", digest("a")],
      ]);
      expect(await scanRow(a.id)).toMatchObject({ status: "running", job_name: `job-${a.id}` });
      expect((await scanRow(a.id)).started_at).toBeTruthy();
      expect((await scanRow(b.id)).status).toBe("queued");
      expect(await runs()).toHaveLength(1);

      // Nothing changes: an idle tick writes no sync_runs row.
      expect(await tick(ctx)).toEqual({ idle: true, running: 1 });
      expect(await runs()).toHaveLength(1);

      runner.states.set(`job-${a.id}`, { state: "succeeded", output });
      expect(await tick(ctx)).toEqual({ done: 1, failed: 0, started: 1, running: 1 });
      const done = await scanRow(a.id);
      expect(done.status).toBe("done");
      expect(done.finished_at).toBeTruthy();
      const stored = await db.selectFrom("image_digests").selectAll().where("id", "=", done.result_digest_id!).executeTakeFirstOrThrow();
      expect(stored).toMatchObject({ image_id: imageId, digest: digest("a"), source: "candidate", os_family: "alpine", scanner_version: "0.76.1" });
      const vulns = await db.selectFrom("vulnerabilities").selectAll().where("digest_id", "=", stored.id).execute();
      expect(vulns).toHaveLength(2);
      expect((await scanRow(b.id)).status).toBe("running");
      const allRuns = await runs();
      expect(allRuns).toHaveLength(2);
      expect(allRuns[1]).toMatchObject({ ok: 1 });
    });

    it("respects a higher concurrency", async () => {
      const { q } = await setup();
      for (const c of ["a", "b", "c"]) await q(c);
      const runner = new FakeRunner();
      expect(await createScanQueue({ runner })(ctxFor({ SCAN_CONCURRENCY: "2" }))).toMatchObject({ started: 2, running: 2 });
    });

    it("marks a runner failure and bad output as failed, and keeps going", async () => {
      const { q } = await setup();
      const a = (await q("a")).scan;
      const b = (await q("b")).scan;
      const runner = new FakeRunner();
      const tick = createScanQueue({ runner });
      const ctx = ctxFor({ SCAN_CONCURRENCY: "2" });
      await tick(ctx);
      runner.states.set(`job-${a.id}`, { state: "failed", error: "Job DeadlineExceeded" });
      runner.states.set(`job-${b.id}`, { state: "succeeded", output: '{"SchemaVersion":2}' });
      expect(await tick(ctx)).toEqual({ done: 0, failed: 2, started: 0, running: 0 });
      expect(await scanRow(a.id)).toMatchObject({ status: "failed", error: "Job DeadlineExceeded" });
      const bad = await scanRow(b.id);
      expect(bad.status).toBe("failed");
      expect(bad.error).toContain("invalid scan output");
      expect(bad.result_digest_id).toBeNull();
    });

    it("marks a scan failed when its Job cannot be created", async () => {
      const { q } = await setup();
      const a = (await q("a")).scan;
      const runner = new FakeRunner();
      runner.startError = new Error("jobs.batch is forbidden");
      expect(await createScanQueue({ runner })(ctxFor())).toEqual({ done: 0, failed: 1, started: 0, running: 0 });
      expect(await scanRow(a.id)).toMatchObject({ status: "failed", error: "could not start the scan: jobs.batch is forbidden" });
    });

    it("re-attaches to running Jobs after a restart, and fails ones that are gone", async () => {
      const { q } = await setup();
      const alive = (await q("a")).scan;
      const gone = (await q("b")).scan;
      const unstarted = (await q("c")).scan;
      const set = (id: number, job_name: string | null) =>
        db.updateTable("scans").set({ status: "running", job_name }).where("id", "=", id).execute();
      await set(alive.id, "job-alive");
      await set(gone.id, "job-gone");
      await set(unstarted.id, null);

      const runner = new FakeRunner();
      runner.states.set("job-alive", { state: "running" });
      const tick = createScanQueue({ runner });
      expect(await tick(ctxFor({ SCAN_CONCURRENCY: "2" }))).toEqual({ done: 0, failed: 2, started: 0, running: 1 });
      expect((await scanRow(alive.id)).status).toBe("running");
      expect(await scanRow(gone.id)).toMatchObject({ status: "failed", error: "scan Job job-gone no longer exists" });
      expect((await scanRow(unstarted.id)).status).toBe("failed");

      runner.states.set("job-alive", { state: "succeeded", output });
      expect(await tick(ctxFor({ SCAN_CONCURRENCY: "2" }))).toMatchObject({ done: 1 });
      expect((await scanRow(alive.id)).status).toBe("done");
    });

    it("keeps a scan running through a transient API error", async () => {
      const { q } = await setup();
      const a = (await q("a")).scan;
      const runner = new FakeRunner();
      const tick = createScanQueue({ runner });
      await tick(ctxFor());
      vi.spyOn(runner, "check").mockRejectedValueOnce(new Error("etcd timeout"));
      expect(await tick(ctxFor())).toEqual({ idle: true, running: 1 });
      expect((await scanRow(a.id)).status).toBe("running");
    });

    it("does not overwrite an operator report of the same digest", async () => {
      const { imageId, q } = await setup();
      const { digestId } = await storeDigest(
        db,
        imageId,
        "operator",
        {
          digest: digest("a"),
          osFamily: "alpine",
          osName: "3.20",
          scannedAt: "2026-11-01T00:00:00Z",
          reportUpdatedAt: "2026-11-01T00:00:00Z",
          scannerVersion: "0.76.1",
          findings: [],
        },
        ["CRITICAL", "HIGH", "MEDIUM"],
      );
      const a = (await q("a")).scan;
      const runner = new FakeRunner();
      const tick = createScanQueue({ runner });
      await tick(ctxFor());
      runner.states.set(`job-${a.id}`, { state: "succeeded", output });
      await tick(ctxFor());
      expect(await scanRow(a.id)).toMatchObject({ status: "done", result_digest_id: digestId });
      const row = await db.selectFrom("image_digests").selectAll().where("id", "=", digestId).executeTakeFirstOrThrow();
      expect(row.source).toBe("operator");
      expect(await db.selectFrom("vulnerabilities").selectAll().execute()).toHaveLength(0);
    });

    it("does nothing once the signal is aborted", async () => {
      const { q } = await setup();
      const a = (await q("a")).scan;
      const abort = new AbortController();
      abort.abort();
      const runner = new FakeRunner();
      expect(await createScanQueue({ runner })(ctxFor({}, abort.signal))).toEqual({ skipped: "stopping" });
      expect((await scanRow(a.id)).status).toBe("queued");
      expect(runner.started).toEqual([]);
    });

    it("records the Trivy server version, at most once per interval", async () => {
      await setup();
      const serverVersion = vi.fn(async () => "0.76.1");
      const tick = createScanQueue({ runner: new FakeRunner(), serverVersion, serverVersionEveryMs: 60_000 });
      await tick(ctxFor());
      await tick(ctxFor());
      expect(serverVersion).toHaveBeenCalledTimes(1);
      expect(await getKv(db, KV.trivyServerVersion)).toBe("0.76.1");
    });

    it("carries on when the Trivy server version is unavailable", async () => {
      await setup();
      const warn = vi.fn();
      const tick = createScanQueue({
        runner: new FakeRunner(),
        serverVersion: async () => {
          throw new Error("connection refused");
        },
        serverVersionEveryMs: 0,
      });
      const ctx = { ...ctxFor(), log: { ...log, info: () => {}, warn } };
      await expect(tick(ctx)).resolves.toEqual({ idle: true, running: 0 });
      await tick(ctx);
      expect(warn).toHaveBeenCalledTimes(1);
      expect(await getKv(db, KV.trivyServerVersion)).toBeUndefined();
    });
  });
}
