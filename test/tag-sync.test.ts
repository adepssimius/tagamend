import { afterEach, describe, expect, it } from "vitest";
import { runTagSync, type TagSyncOptions } from "@/lib/candidates/tag-sync";
import { getConfig } from "@/lib/config";
import type { DB } from "@/lib/db";
import { upsertImage } from "@/lib/db/store";
import { anonymous } from "@/lib/registry/credentials";
import type { Log } from "@/lib/log";
import type { WorkerContext } from "@/lib/worker-context";
import { digestOf, fakeRegistry, type FakeHost, type FakeRegistry } from "./registry-fake";
import { freshDb, testDatabases } from "./helpers";

const HOUR = 3_600_000;
const ZERO_COUNTS = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
const NOW = Date.parse("2026-11-08T12:00:00.000Z");
const config = getConfig({ DATABASE_URL: ":memory:", TAG_SYNC_INTERVAL: "6h" });
const quiet: Log = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const ctxFor = (db: DB, signal = new AbortController().signal): WorkerContext => ({ db, config, log: quiet, signal });

async function workload(db: DB, imageId: number, name: string, tag: string | null, digest: string | null, gone: string | null = null) {
  let digestId: number | null = null;
  if (digest) {
    const row = await db
      .insertInto("image_digests")
      .values({ image_id: imageId, digest, os_family: null, os_name: null, scanned_at: "2026-11-01T00:00:00Z", report_updated_at: null, scanner_version: null, source: "operator", ...ZERO_COUNTS })
      .onConflict((oc) => oc.columns(["image_id", "digest"]).doUpdateSet({ digest }))
      .returning("id")
      .executeTakeFirstOrThrow();
    digestId = row.id;
  }
  await db
    .insertInto("workloads")
    .values({ namespace: "ns", kind: "Deployment", name, container: "c", image_id: imageId, tag, digest_id: digestId, last_seen_at: "2026-11-08T00:00:00Z", gone_at: gone })
    .execute();
}

const tagsOf = (db: DB, imageId: number) => db.selectFrom("tags").selectAll().where("image_id", "=", imageId).orderBy("tag").execute();
const imageRow = (db: DB, id: number) => db.selectFrom("images").selectAll().where("id", "=", id).executeTakeFirstOrThrow();

for (const { name, url } of testDatabases()) {
  describe(`syncTags (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    const hosts = (over: Record<string, FakeHost> = {}): Record<string, FakeHost> => ({
      "registry-1.docker.io": { repos: { "library/app": { tags: ["1.0.0", "1.1.0", "2.0.0", "latest"] } } },
      "ghcr.io": { repos: { "x/y": { tags: ["v1.0.0", "v1.0.1"] } } },
      ...over,
    });
    const run = (reg: FakeRegistry, extra: TagSyncOptions = {}, signal?: AbortSignal) =>
      runTagSync(ctxFor(db, signal), { fetch: reg.fetch, credentials: anonymous, backoff: new Map(), now: () => NOW, batch: 10, ...extra });

    it("records candidates with digests and reasons", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "index.docker.io", "library/app");
      const repo = hosts()["registry-1.docker.io"]!.repos["library/app"]!;
      await workload(db, img, "a", "1.0.0", digestOf(repo, "1.0.0"));
      const reg = fakeRegistry(hosts());

      const out = await run(reg);
      expect(out).toMatchObject({ due: 1, synced: 1, candidates: 2, errors: 0, rateLimited: [] });

      const rows = await tagsOf(db, img);
      expect(rows.map((r) => r.tag)).toEqual(["1.1.0", "2.0.0"]);
      expect(rows.every((r) => r.is_candidate === 1)).toBe(true);
      expect(rows[0]!.digest).toBe(digestOf(repo, "1.1.0"));
      expect(rows[1]!.reason).toMatch(/newest tag of shape N\.N\.N after 1\.0\.0/);

      const image = await imageRow(db, img);
      expect(image.last_tag_sync_at).toBe(new Date(NOW).toISOString());
      expect(image.tag_sync_error).toBeNull();
    });

    it("HEADs only the kept candidates and the running tag", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/z");
      const tags = Array.from({ length: 30 }, (_, i) => `v1.0.${i}`);
      const repo = { tags };
      await workload(db, img, "a", "v1.0.0", digestOf(repo, "v1.0.0"));
      const reg = fakeRegistry({ "ghcr.io": { repos: { "x/z": repo } } });
      await run(reg);
      const heads = reg.calls.filter((c) => c.method === "HEAD").map((c) => c.url.split("/").at(-1));
      expect(heads.sort()).toEqual(["v1.0.0", "v1.0.25", "v1.0.26", "v1.0.27", "v1.0.28", "v1.0.29"].sort());
    });

    it("keeps first_seen_at and drops tags that stop being candidates", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["v1.0.0", "v1.0.1"] };
      await workload(db, img, "a", "v1.0.0", digestOf(repo, "v1.0.0"));
      const reg = fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } });
      await run(reg);
      const first = (await tagsOf(db, img))[0]!;
      expect(first).toMatchObject({ tag: "v1.0.1", first_seen_at: new Date(NOW).toISOString() });

      // A new release arrives, and many hours pass.
      repo.tags.push("v1.0.2");
      const later = NOW + 7 * HOUR;
      await run(reg, { now: () => later });
      let rows = await tagsOf(db, img);
      expect(rows.map((r) => r.tag)).toEqual(["v1.0.1", "v1.0.2"]);
      expect(rows[0]!.first_seen_at).toBe(first.first_seen_at);
      expect(rows[1]!.first_seen_at).toBe(new Date(later).toISOString());

      // The workload catches up; older candidates are no longer newer.
      await db.updateTable("workloads").set({ tag: "v1.0.2" }).execute();
      const repoDigestId = await db
        .insertInto("image_digests")
        .values({ image_id: img, digest: digestOf(repo, "v1.0.2"), os_family: null, os_name: null, scanned_at: "x", report_updated_at: null, scanner_version: null, source: "operator", ...ZERO_COUNTS })
        .returning("id")
        .executeTakeFirstOrThrow();
      await db.updateTable("workloads").set({ digest_id: repoDigestId.id }).execute();
      await run(reg, { now: () => later + 7 * HOUR });
      rows = await tagsOf(db, img);
      expect(rows).toEqual([]);
    });

    it("reports a moved latest as a candidate carrying the new digest", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["latest", "1.0.0"], digests: { latest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbb" } };
      await workload(db, img, "a", "latest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaa");
      const reg = fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } });
      const out = await run(reg);
      expect(out).toMatchObject({ synced: 1, candidates: 1 });
      const rows = await tagsOf(db, img);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ tag: "latest", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbb", is_candidate: 1 });
      expect(rows[0]!.reason).toContain("now points to sha256:bbbbbbbbbbbb");
      expect(rows[0]!.reason).toContain("running sha256:aaaaaaaaaaaa");
      expect(reg.count((c) => c.url.includes("/tags/list"))).toBe(0);
    });

    it("records nothing when latest has not moved", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["latest"], digests: { latest: "sha256:same" } };
      await workload(db, img, "a", "latest", "sha256:same");
      const out = await run(fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } }));
      expect(out).toMatchObject({ synced: 1, candidates: 0 });
      expect(await tagsOf(db, img)).toEqual([]);
    });

    it("flags a workload still on an old digest of a tag others have caught up to", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["latest"], digests: { latest: "sha256:new" } };
      await workload(db, img, "a", "latest", "sha256:new");
      await workload(db, img, "b", "latest", "sha256:old");
      await run(fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } }));
      expect((await tagsOf(db, img))[0]).toMatchObject({ tag: "latest", is_candidate: 1, digest: "sha256:new" });
    });

    it("notes, but does not offer, a floating tag whose running digest is unknown", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      await workload(db, img, "a", "latest", null);
      await run(fakeRegistry({ "ghcr.io": { repos: { "x/y": { tags: ["latest"] } } } }));
      const [row] = await tagsOf(db, img);
      expect(row).toMatchObject({ tag: "latest", is_candidate: 0 });
      expect(row!.reason).toMatch(/not known/);
    });

    it("reports a re-pushed version tag, without listing it as newer", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["3.22"], digests: { "3.22": "sha256:rebuilt" } };
      await workload(db, img, "a", "3.22", "sha256:original");
      await run(fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } }));
      expect((await tagsOf(db, img))[0]).toMatchObject({ tag: "3.22", digest: "sha256:rebuilt", is_candidate: 1 });
    });

    it("counts a digest-only image as pinned and clears old rows", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      await db.insertInto("tags").values({ image_id: img, tag: "old", digest: null, first_seen_at: "x", is_candidate: 1, reason: "r" }).execute();
      await workload(db, img, "a", null, "sha256:aa");
      const reg = fakeRegistry(hosts());
      const out = await run(reg);
      expect(out).toMatchObject({ synced: 1, pinned: 1, candidates: 0 });
      expect(reg.calls).toHaveLength(0);
      expect(await tagsOf(db, img)).toEqual([]);
      expect((await imageRow(db, img)).last_tag_sync_at).not.toBeNull();
    });

    it("merges candidates across running tags, and a running tag may be another's candidate", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "index.docker.io", "gtstef/filebrowser");
      const repo = { tags: ["1.0.2-stable", "1.2.3-stable", "1.3.0-stable", "2.0.1-beta", "2.0.2-beta", "2.0.2-stable"] };
      await workload(db, img, "a", "1.0.2-stable", digestOf(repo, "1.0.2-stable"));
      await workload(db, img, "b", "1.2.3-stable", digestOf(repo, "1.2.3-stable"));
      await workload(db, img, "c", "2.0.1-beta", digestOf(repo, "2.0.1-beta"));
      await run(fakeRegistry({ "registry-1.docker.io": { repos: { "gtstef/filebrowser": repo } } }));
      const rows = await tagsOf(db, img);
      expect(rows.map((r) => r.tag)).toEqual(["1.2.3-stable", "1.3.0-stable", "2.0.2-beta", "2.0.2-stable"]);
      const merged = rows.find((r) => r.tag === "1.3.0-stable")!;
      expect(merged.reason).toContain("after 1.0.2-stable");
      expect(merged.reason).toContain("after 1.2.3-stable");
    });

    it("ignores gone workloads", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      await workload(db, img, "a", "v1.0.0", null, "2026-11-07T00:00:00Z");
      const out = await run(fakeRegistry(hosts()));
      expect(out).toMatchObject({ due: 0, synced: 0 });
      expect((await imageRow(db, img)).last_tag_sync_at).toBeNull();
    });

    it("skips images synced within the interval and picks the oldest first", async () => {
      db = await freshDb(url);
      const fresh = await upsertImage(db, "ghcr.io", "fresh");
      const stale = await upsertImage(db, "ghcr.io", "stale");
      const never = await upsertImage(db, "ghcr.io", "never");
      await db.updateTable("images").set({ last_tag_sync_at: new Date(NOW - HOUR).toISOString() }).where("id", "=", fresh).execute();
      await db.updateTable("images").set({ last_tag_sync_at: new Date(NOW - 7 * HOUR).toISOString() }).where("id", "=", stale).execute();
      for (const [i, id] of [fresh, stale, never].entries()) await workload(db, id, `w${i}`, "latest", null);
      const repos = { fresh: { tags: ["latest"] }, stale: { tags: ["latest"] }, never: { tags: ["latest"] } };
      const reg = fakeRegistry({ "ghcr.io": { repos } });

      const out = await run(reg, { batch: 1 });
      expect(out).toMatchObject({ due: 2, synced: 1 });
      expect((await imageRow(db, never)).last_tag_sync_at).not.toBeNull();
      expect((await imageRow(db, stale)).last_tag_sync_at).toBe(new Date(NOW - 7 * HOUR).toISOString());

      await run(reg, { batch: 1 });
      expect((await imageRow(db, stale)).last_tag_sync_at).toBe(new Date(NOW).toISOString());
      expect((await imageRow(db, fresh)).last_tag_sync_at).toBe(new Date(NOW - HOUR).toISOString());
    });

    it("sizes the batch from the interval, with a floor", async () => {
      db = await freshDb(url);
      const repos: Record<string, { tags: string[] }> = {};
      for (let i = 0; i < 8; i++) {
        const r = `r${i}`;
        repos[r] = { tags: ["latest"] };
        await workload(db, await upsertImage(db, "ghcr.io", r), `w${i}`, "latest", null);
      }
      const out = await run(fakeRegistry({ "ghcr.io": { repos } }), { batch: undefined });
      expect(out).toMatchObject({ due: 8, synced: 3 });
    });

    it("stops a registry for the tick on a rate limit but carries on with others", async () => {
      db = await freshDb(url);
      const a = await upsertImage(db, "index.docker.io", "library/a");
      const b = await upsertImage(db, "index.docker.io", "library/b");
      const c = await upsertImage(db, "ghcr.io", "x/y");
      await workload(db, a, "a", "1.0.0", null);
      await workload(db, b, "b", "1.0.0", null);
      const repo = { tags: ["v1.0.0", "v1.0.1"] };
      await workload(db, c, "c", "v1.0.0", digestOf(repo, "v1.0.0"));
      const reg = fakeRegistry({
        "registry-1.docker.io": { repos: { "library/a": { tags: ["1.0.0"] }, "library/b": { tags: ["1.0.0"] } } },
        "ghcr.io": { repos: { "x/y": repo } },
      });
      reg.intercept = (call) => (new URL(call.url).host === "registry-1.docker.io" ? new Response('{"errors":[{"code":"TOOMANYREQUESTS"}]}', { status: 429 }) : undefined);
      const backoff = new Map<string, number>();

      const out = await run(reg, { backoff });
      expect(out).toMatchObject({ synced: 1, skipped: 1, errors: 0, rateLimited: ["registry-1.docker.io"] });
      expect(reg.count((x) => new URL(x.url).host === "registry-1.docker.io")).toBe(1);

      const first = await imageRow(db, a);
      expect(first.tag_sync_error).toMatch(/429/);
      expect(first.last_tag_sync_at).toBeNull();
      expect((await imageRow(db, b)).tag_sync_error).toBeNull();
      expect((await imageRow(db, c)).last_tag_sync_at).not.toBeNull();

      // The backoff holds across ticks, then lapses.
      reg.calls.length = 0;
      await run(reg, { backoff, now: () => NOW + 60_000 });
      expect(reg.count((x) => new URL(x.url).host === "registry-1.docker.io")).toBe(0);
      await run(reg, { backoff, now: () => NOW + 16 * 60_000 });
      expect(reg.count((x) => new URL(x.url).host === "registry-1.docker.io")).toBe(1);
    });

    it("honours Retry-After for the backoff", async () => {
      db = await freshDb(url);
      const a = await upsertImage(db, "ghcr.io", "x/y");
      await workload(db, a, "a", "1.0.0", null);
      const reg = fakeRegistry({ "ghcr.io": { repos: { "x/y": { tags: ["1.0.0"] } } } });
      reg.intercept = () => new Response("", { status: 429, headers: { "retry-after": "60" } });
      const backoff = new Map<string, number>();
      await run(reg, { backoff });
      expect(backoff.get("ghcr.io")).toBe(NOW + 60_000);
    });

    it("keeps prior candidates when a rate limit interrupts the HEADs", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["v1.0.0", "v1.0.1", "v1.0.2"] };
      await workload(db, img, "a", "v1.0.0", digestOf(repo, "v1.0.0"));
      await db.insertInto("tags").values({ image_id: img, tag: "v1.0.1", digest: "sha256:prior", first_seen_at: "x", is_candidate: 1, reason: "r" }).execute();
      const reg = fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } });
      reg.intercept = (c) => (c.method === "HEAD" && c.url.endsWith("v1.0.2") ? new Response("", { status: 429 }) : undefined);
      await run(reg);
      expect((await tagsOf(db, img)).map((r) => [r.tag, r.digest])).toEqual([["v1.0.1", "sha256:prior"]]);
    });

    it("records other errors and waits for the next interval", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "gone/repo");
      await workload(db, img, "a", "1.0.0", null);
      const out = await run(fakeRegistry({ "ghcr.io": { repos: {} } }));
      expect(out).toMatchObject({ synced: 0, errors: 1, rateLimited: [] });
      const row = await imageRow(db, img);
      expect(row.tag_sync_error).toMatch(/404/);
      expect(row.last_tag_sync_at).toBe(new Date(NOW).toISOString());
    });

    it("clears a stale error once a sync succeeds", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      await db.updateTable("images").set({ tag_sync_error: "old" }).where("id", "=", img).execute();
      await workload(db, img, "a", "latest", null);
      await run(fakeRegistry({ "ghcr.io": { repos: { "x/y": { tags: ["latest"] } } } }));
      expect((await imageRow(db, img)).tag_sync_error).toBeNull();
    });

    it("keeps a candidate with no digest when its HEAD fails", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const repo = { tags: ["v1.0.0", "v1.0.1"] };
      await workload(db, img, "a", "v1.0.0", digestOf(repo, "v1.0.0"));
      const reg = fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } });
      reg.intercept = (c) => (c.method === "HEAD" && c.url.endsWith("v1.0.1") ? new Response("", { status: 404 }) : undefined);
      await run(reg);
      const [row] = await tagsOf(db, img);
      expect(row).toMatchObject({ tag: "v1.0.1", digest: null, is_candidate: 1 });
      expect(row!.reason).toMatch(/digest not available/);
    });

    it("tolerates a running tag that no longer exists upstream", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "x/y");
      await workload(db, img, "a", "v1.0.0", "sha256:aa");
      const repo = { tags: ["v1.0.1"] };
      const out = await run(fakeRegistry({ "ghcr.io": { repos: { "x/y": repo } } }));
      expect(out).toMatchObject({ synced: 1, errors: 0 });
      expect((await tagsOf(db, img)).map((r) => r.tag)).toEqual(["v1.0.1"]);
    });

    it("stops between images when the signal aborts", async () => {
      db = await freshDb(url);
      const a = await upsertImage(db, "ghcr.io", "a");
      const b = await upsertImage(db, "ghcr.io", "b");
      await workload(db, a, "a", "latest", null);
      await workload(db, b, "b", "latest", null);
      const abort = new AbortController();
      const reg = fakeRegistry({ "ghcr.io": { repos: { a: { tags: ["latest"] }, b: { tags: ["latest"] } } } });
      reg.intercept = () => {
        abort.abort();
        return undefined;
      };
      const out = await run(reg, {}, abort.signal);
      expect(out).toMatchObject({ synced: 1 });
      expect((await imageRow(db, b)).last_tag_sync_at).toBeNull();
    });

    it("does not record an error for a request aborted by shutdown", async () => {
      db = await freshDb(url);
      const a = await upsertImage(db, "ghcr.io", "a");
      await workload(db, a, "a", "latest", null);
      const abort = new AbortController();
      const reg = fakeRegistry({ "ghcr.io": { repos: {} } });
      reg.fetch = (async () => {
        abort.abort();
        throw new DOMException("aborted", "AbortError");
      }) as typeof fetch;
      const out = await run(reg, {}, abort.signal);
      expect(out).toMatchObject({ synced: 0, errors: 0 });
      expect((await imageRow(db, a)).tag_sync_error).toBeNull();
    });
  });
}
