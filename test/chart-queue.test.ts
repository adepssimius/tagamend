import { afterEach, describe, expect, it } from "vitest";
import type { ChartImage, ChartImageChange, PinnedImage } from "@/lib/charts/types";
import { getConfig } from "@/lib/config";
import { type DB, now } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { queueChartPullRequest } from "@/lib/gitops/chart-enqueue";
import { refreshChartPrStates, refreshPrStates } from "@/lib/gitops/pr-state";
import { runPrQueue } from "@/lib/gitops/queue";
import { log } from "@/lib/log";
import type { Finding } from "@/lib/trivy/finding";
import type { WorkerContext } from "@/lib/worker-context";
import { FakeGitHub } from "./fake-github";
import { freshDb, testDatabases } from "./helpers";

const f = (vulnId: string, severity: Finding["severity"]): Finding => ({
  vulnId,
  package: "openssl",
  installedVersion: "1",
  fixedVersion: null,
  severity,
  score: null,
  title: `title of ${vulnId}`,
  link: null,
});

const HR = `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: demo
spec:
  chart:
    spec:
      chart: demo
      version: 1.2.0 # chart
      sourceRef: {kind: HelmRepository, name: example}
  values:
    proxy:
      image:
        tag: "0.4.0"
`;
const REPO = {
  "apps/demo/helmrelease.yaml": HR,
  "apps/demo/kustomization.yaml": "namespace: apps\nresources: [helmrelease.yaml]\n",
  "README.md": "not yaml",
};

const img = (repository: string, tag: string, digest: string | null): ChartImage => ({
  key: "",
  kind: "Deployment",
  name: "",
  ref: `ghcr.io/${repository}:${tag}`,
  registry: "ghcr.io",
  repository,
  tag,
  digest,
});

async function setup(db: DB) {
  const server = await upsertImage(db, "ghcr.io", "example/demo-server");
  const store = (digest: string, findings: Finding[], source: "operator" | "candidate") =>
    storeDigest(db, server, source, { digest, osFamily: null, osName: null, scannedAt: now(), reportUpdatedAt: null, scannerVersion: null, findings }, ["CRITICAL", "HIGH", "MEDIUM"]);
  const running = (await store("sha256:run", [f("CVE-1", "CRITICAL"), f("CVE-2", "HIGH")], "operator")).digestId;
  const cand = (await store("sha256:cand", [f("CVE-2", "HIGH"), f("CVE-3", "MEDIUM")], "candidate")).digestId;
  await db
    .insertInto("workloads")
    .values({ namespace: "apps", kind: "Deployment", name: "demo-server", container: "app", image_id: server, tag: "1.2.0", digest_id: running, last_seen_at: now(), gone_at: null })
    .execute();
  await db
    .insertInto("scans")
    .values({ image_id: server, tag: "1.3.0", digest: "sha256:cand", status: "done", requested_by: "me", requested_at: now(), started_at: null, finished_at: now(), job_name: null, error: null, result_digest_id: cand })
    .execute();

  const chart = await db
    .insertInto("charts")
    .values({
      namespace: "apps",
      name: "demo",
      chart: "demo",
      version: "1.2.0",
      installed_version: "1.2.0",
      source_kind: "HelmRepository",
      source_url: "https://charts.example.com",
      last_sync_at: now(),
      sync_error: null,
      current_images: null,
      render_note: null,
      gone_at: null,
    })
    .returning("id")
    .executeTakeFirstOrThrow();
  const changes: ChartImageChange[] = [
    {
      key: "Deployment/demo-server:spec.template.spec.containers[0].image",
      kind: "Deployment",
      name: "demo-server",
      from: img("example/demo-server", "1.2.0", "sha256:run"),
      to: img("example/demo-server", "1.3.0", "sha256:cand"),
    },
    {
      key: "Deployment/demo-worker:spec.template.spec.containers[0].image",
      kind: "Deployment",
      name: "demo-worker",
      from: img("example/demo-worker", "1.2.0", null),
      to: img("example/demo-worker", "1.3.0", "sha256:unscanned"),
    },
  ];
  const pinned: PinnedImage[] = [
    {
      key: "Deployment/demo-proxy:spec.template.spec.containers[0].image",
      kind: "Deployment",
      name: "demo-proxy",
      valuesPath: ["proxy", "image", "tag"],
      pinnedTag: "0.4.0",
      chartDefault: img("example/demo-proxy", "0.5.0", null),
    },
  ];
  const candidate = await db
    .insertInto("chart_candidates")
    .values({
      chart_id: chart.id,
      version: "2.0.0",
      app_version: null,
      first_seen_at: now(),
      is_candidate: 1,
      reason: null,
      rendered_at: now(),
      render_error: null,
      changes: JSON.stringify(changes),
      pinned: JSON.stringify(pinned),
    })
    .returning("id")
    .executeTakeFirstOrThrow();
  return { chartId: chart.id, candidateId: candidate.id };
}

const ctxFor = (db: DB): WorkerContext => ({
  db,
  config: getConfig({ DATABASE_URL: ":memory:", GITOPS_REPO: "o/r", GITHUB_TOKEN: "t", APP_URL: "https://tagamend.example" }),
  log,
  signal: new AbortController().signal,
});

for (const { name, url } of testDatabases()) {
  describe(`chart PR queue (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("dedupes requests per candidate and pin choice", async () => {
      db = await freshDb(url);
      const { candidateId, chartId } = await setup(db);
      const a = await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: false });
      expect(a.created).toBe(true);
      expect(a.pr).toMatchObject({ chart_id: chartId, to_version: "2.0.0", update_pins: 0, status: "queued" });
      expect((await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: false })).created).toBe(false);
      expect((await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: true })).created).toBe(true);

      // A failed one, or a merged one, does not block a new request.
      await db.updateTable("chart_pull_requests").set({ status: "failed" }).where("id", "=", a.pr.id).execute();
      const b = await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: false });
      expect(b.created).toBe(true);
      await db.updateTable("chart_pull_requests").set({ status: "opened", pr_state: "merged" }).where("id", "=", b.pr.id).execute();
      expect((await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: false })).created).toBe(true);

      await expect(queueChartPullRequest(db, { candidateId: 999, requestedBy: "ben", updatePins: false })).rejects.toThrow("does not exist");
      await db.updateTable("charts").set({ gone_at: now() }).execute();
      await expect(queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: true })).rejects.toThrow("no longer exists");
    });

    it("opens a PR that bumps the version and moves pins, after any tag PR", async () => {
      db = await freshDb(url);
      const { candidateId, chartId } = await setup(db);
      await db.insertInto("kev").values({ cve_id: "CVE-1", vulnerability_name: "x", vendor_project: null, product: null, date_added: "2026-01-01", due_date: null, known_ransomware: 0, short_description: null }).execute();
      const { pr } = await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: true });
      const gh = new FakeGitHub(REPO);
      expect(await runPrQueue(ctxFor(db), { github: gh })).toMatchObject({ opened: 1, kind: "chart" });

      expect(gh.commits).toHaveLength(1);
      expect(gh.commits[0]!.branch).toBe("tagamend/chart-demo-2.0.0-pins");
      expect([...gh.commits[0]!.files]).toEqual([
        ["apps/demo/helmrelease.yaml", HR.replace("version: 1.2.0 # chart", "version: 2.0.0 # chart").replace('tag: "0.4.0"', 'tag: "0.5.0"')],
      ]);
      const { title, body } = gh.prs[0]!;
      expect(title).toBe("demo: bump chart demo 1.2.0 to 2.0.0");
      expect(body).toContain("- **Deployment/demo-server**: `ghcr.io/example/demo-server:1.2.0` to `ghcr.io/example/demo-server:1.3.0`");
      expect(body).toContain("  - **Fixes:** 1 critical, 0 high, 0 medium, of which **1 known exploited**");
      expect(body).toContain("  - **Still present:** 0 critical, 1 high, 0 medium");
      expect(body).toContain("  - **New:** 0 critical, 0 high, 1 medium");
      expect(body).toContain("- **Deployment/demo-worker**: `ghcr.io/example/demo-worker:1.2.0` to `ghcr.io/example/demo-worker:1.3.0`\n  - Not scanned yet.");
      expect(body).toContain("- **Deployment/demo-proxy** at `spec.values.proxy.image.tag`: pinned to `0.4.0`, this PR moves it to `0.5.0`, the chart's default.");
      expect(body).toContain("**This is a major version bump (1 to 2).**");
      expect(body).toContain("CRD changes are not covered.");
      expect(body).toContain(`Chart page: https://tagamend.example/charts/${chartId}`);
      expect(body).toContain("Opened by tagamend for ben.");

      const row = await db.selectFrom("chart_pull_requests").selectAll().where("id", "=", pr.id).executeTakeFirstOrThrow();
      expect(row).toMatchObject({ status: "opened", pr_state: "open", pr_number: 7, branch: "tagamend/chart-demo-2.0.0-pins", error: null });
      expect(JSON.parse(row.edits!).map((e: { line: number }) => e.line)).toEqual([9, 14]);
      expect(await runPrQueue(ctxFor(db), { github: gh })).toEqual({ idle: true });

      // State reads back like a tag PR's: on demand, fresh for 30s, final once merged.
      let t = Date.parse("2030-01-01T00:00:00Z");
      const opts = { repo: "o/r", token: undefined, github: gh, nowMs: () => t };
      gh.states.set(7, "merged");
      expect(await refreshChartPrStates(db, { ...opts, chartId })).toBe(1);
      expect(gh.stateCalls).toBe(1);
      t += 600_000;
      expect(await refreshPrStates(db, opts)).toBe(0);
      expect(gh.stateCalls).toBe(1);
    });

    it("leaves pins alone when not asked, and the status page refresh covers chart PRs", async () => {
      db = await freshDb(url);
      const { candidateId } = await setup(db);
      await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: false });
      const gh = new FakeGitHub(REPO);
      await runPrQueue(ctxFor(db), { github: gh });
      expect(gh.commits[0]!.branch).toBe("tagamend/chart-demo-2.0.0");
      expect(gh.commits[0]!.files.get("apps/demo/helmrelease.yaml")).toContain('tag: "0.4.0"');
      expect(gh.prs[0]!.body).toContain("left at `0.4.0`; the chart's default is `0.5.0`");

      const t = Date.parse("2030-01-01T00:00:00Z");
      gh.states.set(7, "closed");
      expect(await refreshPrStates(db, { repo: "o/r", token: undefined, github: gh, nowMs: () => t })).toBe(1);
      expect((await db.selectFrom("chart_pull_requests").select("pr_state").executeTakeFirstOrThrow()).pr_state).toBe("closed");
    });

    it("fails with the reason when the HelmRelease is not in the repo", async () => {
      db = await freshDb(url);
      const { candidateId } = await setup(db);
      const { pr } = await queueChartPullRequest(db, { candidateId, requestedBy: "ben", updatePins: false });
      const gh = new FakeGitHub({ "apps/other.yaml": "kind: ConfigMap\nmetadata:\n  name: x\n" });
      expect(await runPrQueue(ctxFor(db), { github: gh })).toMatchObject({ failed: 1, kind: "chart" });
      const row = await db.selectFrom("chart_pull_requests").selectAll().where("id", "=", pr.id).executeTakeFirstOrThrow();
      expect(row.status).toBe("failed");
      expect(row.error).toBe("no HelmRelease apps/demo in the repo. It may be deployed from outside the repo. (in o/r@main)");
      expect(gh.commits).toHaveLength(0);
    });
  });
}
