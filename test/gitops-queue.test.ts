import { afterEach, describe, expect, it } from "vitest";
import { getConfig } from "@/lib/config";
import { type DB, now } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { queuePullRequest } from "@/lib/gitops/enqueue";
import { refreshPrStates } from "@/lib/gitops/pr-state";
import { branchName, runPrQueue } from "@/lib/gitops/queue";
import { log } from "@/lib/log";
import type { Finding } from "@/lib/trivy/finding";
import type { WorkerContext } from "@/lib/worker-context";
import { freshDb, testDatabases } from "./helpers";
import { FakeGitHub as BaseFakeGitHub } from "./fake-github";

const f = (vulnId: string, severity: Finding["severity"], fixedVersion: string | null = null): Finding => ({
  vulnId,
  package: "openssl",
  installedVersion: "1",
  fixedVersion,
  severity,
  score: null,
  title: `title of ${vulnId}`,
  link: null,
});

const REPO_FILES: Record<string, string> = {
  "apps/books/deployment.yaml": "      containers:\n        - image: ghcr.io/example/books:2.32.1\n",
  "README.md": "not yaml",
};

class FakeGitHub extends BaseFakeGitHub {
  constructor(files: Record<string, string> = REPO_FILES) {
    super(files);
  }
}

async function setup(db: DB) {
  const img = await upsertImage(db, "ghcr.io", "example/books");
  const store = (digest: string, findings: Finding[], source: "operator" | "candidate") =>
    storeDigest(db, img, source, { digest, osFamily: null, osName: null, scannedAt: now(), reportUpdatedAt: null, scannerVersion: null, findings }, ["CRITICAL", "HIGH", "MEDIUM"]);
  const running = (await store("sha256:run", [f("CVE-1", "CRITICAL"), f("CVE-2", "HIGH", "9"), f("CVE-3", "MEDIUM")], "operator")).digestId;
  const cand = (await store("sha256:cand", [f("CVE-2", "HIGH"), f("CVE-4", "HIGH")], "candidate")).digestId;
  await db
    .insertInto("workloads")
    .values({ namespace: "media", kind: "Deployment", name: "books", container: "app", image_id: img, tag: "2.32.1", digest_id: running, last_seen_at: now(), gone_at: null })
    .execute();
  const scan = await db
    .insertInto("scans")
    .values({ image_id: img, tag: "2.37.2", digest: "sha256:cand", status: "done", requested_by: "me", requested_at: now(), started_at: null, finished_at: now(), job_name: null, error: null, result_digest_id: cand })
    .returning("id")
    .executeTakeFirstOrThrow();
  return { img, scanId: scan.id };
}

const ctxFor = (db: DB, env: Record<string, string> = {}): WorkerContext => ({
  db,
  config: getConfig({ DATABASE_URL: ":memory:", GITOPS_REPO: "o/r", GITHUB_TOKEN: "t", APP_URL: "https://tagamend.example", ...env }),
  log,
  signal: new AbortController().signal,
});

for (const { name, url } of testDatabases()) {
  describe(`PR queue (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("commits the edit and opens a PR carrying the scan's diff", async () => {
      db = await freshDb(url);
      const { scanId } = await setup(db);
      const { pr, created } = await queuePullRequest(db, { scanId, requestedBy: "ben" });
      expect(created).toBe(true);
      expect((await queuePullRequest(db, { scanId, requestedBy: "ben" })).created).toBe(false);

      await db.insertInto("kev").values({ cve_id: "CVE-1", vulnerability_name: "x", vendor_project: null, product: null, date_added: "2026-01-01", due_date: null, known_ransomware: 0, short_description: null }).execute();
      const gh = new FakeGitHub();
      expect(await runPrQueue(ctxFor(db), { github: gh })).toMatchObject({ opened: 1 });

      expect(gh.commits).toHaveLength(1);
      expect(gh.commits[0]!.branch).toBe("tagamend/books-2.37.2");
      expect([...gh.commits[0]!.files]).toEqual([
        ["apps/books/deployment.yaml", "      containers:\n        - image: ghcr.io/example/books:2.37.2\n"],
      ]);
      const body = gh.prs[0]!.body;
      expect(gh.prs[0]!.title).toBe("books: bump 2.32.1 to 2.37.2");
      expect(gh.prs[0]!.base).toBe("main");
      expect(body).toContain("**Fixes:** 1 critical, 0 high, 1 medium, of which **1 known exploited**");
      expect(body).toContain("[CVE-1](https://osv.dev/vulnerability/CVE-1) **exploited**");
      expect(body).toContain("**Still present:** 0 critical, 1 high, 0 medium. 1 of these have a fix upstream");
      expect(body).toContain("**New in 2.37.2:** 0 critical, 1 high, 0 medium");
      expect(body).toContain("https://tagamend.example/scans/");
      expect(body).toContain("Opened by tagamend for ben.");
      expect(body).not.toContain("Not in this repo");

      const row = await db.selectFrom("pull_requests").selectAll().where("id", "=", pr.id).executeTakeFirstOrThrow();
      expect(row).toMatchObject({ status: "opened", pr_number: 7, pr_url: "https://github.com/o/r/pull/7", branch: "tagamend/books-2.37.2" });
      expect(await runPrQueue(ctxFor(db), { github: gh })).toEqual({ idle: true });
    });

    it("reads back PR state on demand, reusing a fresh check and never rechecking a final one", async () => {
      db = await freshDb(url);
      const { scanId, img } = await setup(db);
      await queuePullRequest(db, { scanId, requestedBy: "ben" });
      const gh = new FakeGitHub();
      await runPrQueue(ctxFor(db), { github: gh });
      const state = async () => (await db.selectFrom("pull_requests").select("pr_state").executeTakeFirstOrThrow()).pr_state;
      expect(await state()).toBe("open");

      let t = Date.parse("2030-01-01T00:00:00Z");
      const opts = { repo: "o/r", token: undefined, github: gh, imageId: img, nowMs: () => t };
      expect(await refreshPrStates(db, opts)).toBe(0);
      expect(gh.stateCalls).toBe(1);
      t += 10_000; // fresh: no call
      await refreshPrStates(db, opts);
      expect(gh.stateCalls).toBe(1);

      gh.states.set(7, "merged");
      t += 60_000;
      expect(await refreshPrStates(db, opts)).toBe(1);
      expect(await state()).toBe("merged");
      t += 600_000; // merged is final
      await refreshPrStates(db, opts);
      expect(gh.stateCalls).toBe(2);
      expect(await refreshPrStates(db, { ...opts, imageId: img + 1 })).toBe(0);
    });

    it("names workloads the repo does not define", async () => {
      db = await freshDb(url);
      const { scanId, img } = await setup(db);
      const dig = (await db.selectFrom("workloads").select("digest_id").executeTakeFirstOrThrow()).digest_id;
      await db.insertInto("workloads").values({ namespace: "scratch", kind: "Deployment", name: "books", container: "app", image_id: img, tag: "2.32.1", digest_id: dig, last_seen_at: now(), gone_at: null }).execute();
      await queuePullRequest(db, { scanId, requestedBy: "ben" });
      const gh = new FakeGitHub({
        "apps/books/deployment.yaml": "kind: Deployment\nmetadata:\n  name: books\n  namespace: media\nspec:\n  template:\n    spec:\n      containers:\n        - image: ghcr.io/example/books:2.32.1\n",
      });
      expect(await runPrQueue(ctxFor(db), { github: gh })).toMatchObject({ opened: 1 });
      expect(gh.prs[0]!.body).toContain("- `scratch/books` runs this image but is not defined in `o/r`.");
      expect(gh.prs[0]!.body).not.toContain("`media/books` runs");
    });

    it("fails with a reason when the repo does not reference the image", async () => {
      db = await freshDb(url);
      const { scanId } = await setup(db);
      const { pr } = await queuePullRequest(db, { scanId, requestedBy: "ben" });
      const gh = new FakeGitHub({ "apps/other.yaml": "image: ghcr.io/example/other:1.0\n" });
      expect(await runPrQueue(ctxFor(db), { github: gh })).toMatchObject({ failed: 1 });
      const row = await db.selectFrom("pull_requests").selectAll().where("id", "=", pr.id).executeTakeFirstOrThrow();
      expect(row.status).toBe("failed");
      expect(row.error).toContain("Helm chart's defaults");
      expect(gh.commits).toHaveLength(0);
      // A failed request can be retried.
      expect((await queuePullRequest(db, { scanId, requestedBy: "ben" })).created).toBe(true);
    });

    it("is off without GITOPS_REPO and refuses a scan that is not done", async () => {
      db = await freshDb(url);
      const { scanId } = await setup(db);
      expect(await runPrQueue({ ...ctxFor(db), config: getConfig({ DATABASE_URL: ":memory:" }) })).toEqual({ idle: true, disabled: true });
      await db.updateTable("scans").set({ status: "running" }).where("id", "=", scanId).execute();
      await expect(queuePullRequest(db, { scanId, requestedBy: "ben" })).rejects.toThrow("not done");
    });
  });
}

describe("branchName", () => {
  it("makes names git accepts", () => {
    expect(branchName("linuxserver/sonarr", "4.0.15.2941-ls290")).toBe("tagamend/sonarr-4.0.15.2941-ls290");
    expect(branchName("a/b", "v1+build")).toBe("tagamend/b-v1-build");
    expect(branchName("a/nvr", "stable", `sha256:${"f".repeat(64)}`)).toBe("tagamend/nvr-stable-ffffffffffff");
  });
});
