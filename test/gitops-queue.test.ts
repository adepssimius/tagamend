import { afterEach, describe, expect, it } from "vitest";
import { getConfig } from "@/lib/config";
import { type DB, now } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { queuePullRequest } from "@/lib/gitops/enqueue";
import type { GitHub } from "@/lib/gitops/github";
import { branchName, runPrQueue } from "@/lib/gitops/queue";
import { log } from "@/lib/log";
import type { Finding } from "@/lib/trivy/finding";
import type { WorkerContext } from "@/lib/worker-context";
import { freshDb, testDatabases } from "./helpers";
import { repoTarball } from "./tar-writer";

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

const REPO_FILES = {
  "apps/books/deployment.yaml": "      containers:\n        - image: ghcr.io/example/books:2.32.1\n",
  "README.md": "not yaml",
};

class FakeGitHub implements GitHub {
  commits: { branch: string; message: string; files: Map<string, string> }[] = [];
  prs: { head: string; base: string; title: string; body: string }[] = [];
  existingBranches = new Set<string>();
  constructor(private files: Record<string, string> = REPO_FILES) {}
  async branchSha() {
    return "base-sha";
  }
  async tarball() {
    return repoTarball(this.files);
  }
  async commitToNewBranch(o: { baseSha: string; branch: string; message: string; files: Map<string, string> }) {
    this.commits.push(o);
    this.existingBranches.add(o.branch);
    return "new-sha";
  }
  async findOpenPr() {
    return null;
  }
  async openPr(o: { head: string; base: string; title: string; body: string }) {
    this.prs.push(o);
    return { number: 7, url: "https://github.com/o/r/pull/7" };
  }
  async branchExists(b: string) {
    return this.existingBranches.has(b);
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

      const row = await db.selectFrom("pull_requests").selectAll().where("id", "=", pr.id).executeTakeFirstOrThrow();
      expect(row).toMatchObject({ status: "opened", pr_number: 7, pr_url: "https://github.com/o/r/pull/7", branch: "tagamend/books-2.37.2" });
      expect(await runPrQueue(ctxFor(db), { github: gh })).toEqual({ idle: true });
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
  });
});
