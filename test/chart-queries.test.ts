import { afterEach, describe, expect, it } from "vitest";
import type { DB } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import type { ChartImage, ChartImageChange, PinnedImage } from "@/lib/charts/types";
import { chartIdsByManagedBy, chartsWithCandidate, getChartList, getChartPage, parseHelmRelease } from "@/lib/queries/charts";
import type { Severity } from "@/lib/config";
import type { Finding } from "@/lib/trivy/finding";
import { freshDb, testDatabases } from "./helpers";

const T = "2026-11-01T00:00:00.000Z";
const f = (vulnId: string, pkg: string, severity: Severity): Finding => ({
  vulnId,
  package: pkg,
  installedVersion: "1",
  fixedVersion: null,
  severity,
  score: null,
  title: null,
  link: null,
});

async function digest(db: DB, imageId: number, name: string, findings: Finding[], source: "operator" | "candidate" = "operator") {
  const scan = { digest: name, osFamily: null, osName: null, scannedAt: T, reportUpdatedAt: null, scannerVersion: null, findings };
  return (await storeDigest(db, imageId, source, scan, ["CRITICAL", "HIGH", "MEDIUM"])).digestId;
}

async function workload(db: DB, imageId: number, digestId: number, name: string, managedBy: string | null, ns = "apps") {
  await db
    .insertInto("workloads")
    .values({
      namespace: ns,
      kind: "Deployment",
      name,
      container: "app",
      image_id: imageId,
      tag: "1.0",
      digest_id: digestId,
      last_seen_at: T,
      managed_by: managedBy,
      gone_at: null,
    })
    .execute();
}

const img = (name: string, repository: string, tag: string, digestName: string | null): ChartImage => ({
  key: `Deployment/${name}:spec.template.spec.containers[0].image`,
  kind: "Deployment",
  name,
  ref: `ghcr.io/${repository}:${tag}`,
  registry: "ghcr.io",
  repository,
  tag,
  digest: digestName,
});
const change = (from: ChartImage | null, to: ChartImage | null): ChartImageChange => ({
  key: (to ?? from)!.key,
  kind: (to ?? from)!.kind,
  name: (to ?? from)!.name,
  from,
  to,
});

async function chart(db: DB, ns: string, name: string, opts: { gone?: boolean; images?: ChartImage[] } = {}) {
  return (
    await db
      .insertInto("charts")
      .values({
        namespace: ns,
        name,
        chart: name,
        version: "1.0.0",
        installed_version: "1.0.0",
        source_kind: "HelmRepository",
        source_url: "https://charts.example.com",
        last_sync_at: T,
        sync_error: null,
        current_images: JSON.stringify(opts.images ?? []),
        render_note: null,
        gone_at: opts.gone ? T : null,
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;
}

async function candidate(db: DB, chartId: number, version: string, opts: { changes?: ChartImageChange[]; pinned?: PinnedImage[]; isCandidate?: boolean } = {}) {
  return (
    await db
      .insertInto("chart_candidates")
      .values({
        chart_id: chartId,
        version,
        app_version: null,
        first_seen_at: T,
        is_candidate: opts.isCandidate === false ? 0 : 1,
        reason: "r",
        rendered_at: T,
        render_error: null,
        changes: JSON.stringify(opts.changes ?? []),
        pinned: JSON.stringify(opts.pinned ?? []),
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;
}

async function doneScan(db: DB, imageId: number, digestName: string, resultId: number | null, status: "done" | "queued" = "done") {
  await db
    .insertInto("scans")
    .values({
      image_id: imageId,
      tag: "t",
      digest: digestName,
      status,
      requested_by: "t",
      requested_at: T,
      started_at: null,
      finished_at: null,
      job_name: null,
      error: null,
      result_digest_id: resultId,
    })
    .execute();
}

describe("parseHelmRelease", () => {
  it("reads only HelmRelease owners", () => {
    expect(parseHelmRelease("HelmRelease apps/web")).toEqual({ namespace: "apps", name: "web" });
    expect(parseHelmRelease("Kustomization flux-system/apps")).toBeNull();
    expect(parseHelmRelease("none")).toBeNull();
    expect(parseHelmRelease(null)).toBeNull();
  });
});

for (const { name, url } of testDatabases()) {
  describe(`chart queries (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    /** apps/web runs a/web (2 CVEs) and a/side; 2.0.0 changes both, only a/web's new digest is scanned. */
    async function setup() {
      db = await freshDb(url);
      const web = await upsertImage(db, "ghcr.io", "a/web");
      const side = await upsertImage(db, "ghcr.io", "a/side");
      const webRun = await digest(db, web, "sha256:web1", [f("CVE-1", "x", "CRITICAL"), f("CVE-2", "y", "HIGH")]);
      const sideRun = await digest(db, side, "sha256:side1", [f("CVE-3", "z", "MEDIUM")]);
      await workload(db, web, webRun, "web", "HelmRelease apps/web");
      await workload(db, side, sideRun, "side", "HelmRelease apps/web");
      await workload(db, web, webRun, "other", "Kustomization flux-system/apps");
      const webCand = await digest(db, web, "sha256:web2", [f("CVE-2", "y", "HIGH"), f("CVE-4", "w", "MEDIUM")], "candidate");
      await doneScan(db, web, "sha256:web2", webCand);

      const chartId = await chart(db, "apps", "web", { images: [img("web", "a/web", "1.0", "sha256:web1")] });
      const quiet = await chart(db, "apps", "quiet");
      await chart(db, "apps", "retired", { gone: true });
      const older = await candidate(db, chartId, "1.5.0", { changes: [change(img("web", "a/web", "1.0", "sha256:web1"), img("web", "a/web", "1.5", "sha256:web15"))] });
      const newest = await candidate(db, chartId, "2.0.0", {
        changes: [
          change(img("web", "a/web", "1.0", "sha256:web1"), img("web", "a/web", "2.0", "sha256:web2")),
          change(img("side", "a/side", "1.0", "sha256:side1"), img("side", "a/side", "2.0", "sha256:side2")),
        ],
        pinned: [
          { key: "Deployment/web:x", kind: "Deployment", name: "web", valuesPath: ["image", "tag"], pinnedTag: "1.0", chartDefault: img("web", "a/web", "2.0", "sha256:web2") },
        ],
      });
      await candidate(db, chartId, "3.0.0-rc.1", { isCandidate: false });
      return { chartId, quiet, older, newest, web };
    }

    it("lists live HelmReleases with the newest candidate and its scan state", async () => {
      const { chartId, quiet, newest } = await setup();
      await db
        .insertInto("chart_pull_requests")
        .values({ chart_id: chartId, candidate_id: newest, to_version: "2.0.0", update_pins: 0, status: "queued", requested_by: "t", requested_at: T })
        .execute();

      const rows = await getChartList(db);
      expect(rows.map((r) => r.chart.id)).toEqual([chartId, quiet]);
      const r = rows[0]!;
      expect(r.candidateCount).toBe(2);
      expect(r.best?.candidate.version).toBe("2.0.0");
      expect(r.best).toMatchObject({ changed: 2, scannable: 2, scanned: 1, state: "partial" });
      // Only the HelmRelease's workloads count: web and side, not "other".
      expect(r.workloads).toBe(2);
      expect(r.running).toEqual({ critical: 1, high: 1, medium: 1, exploited: 0 });
      expect(r.pr?.status).toBe("queued");
      expect(rows[1]!.best).toBeNull();
      expect(await chartsWithCandidate(db)).toBe(1);
    });

    it("shows the newest candidate's per-image diff and the pinned image's default", async () => {
      const { chartId, older } = await setup();
      const page = (await getChartPage(db, chartId))!;
      expect(page.candidates.map((c) => c.candidate.version)).toEqual(["2.0.0", "1.5.0"]);
      expect(page.others.map((c) => c.version)).toEqual(["3.0.0-rc.1"]);
      expect(page.currentImages[0]!.imageId).not.toBeNull();
      const sel = page.selected!;
      expect(sel.candidate.version).toBe("2.0.0");
      const web = sel.diffs.find((d) => d.change.name === "web")!;
      expect(web.running).toEqual({ critical: 1, high: 1, medium: 0, exploited: 0 });
      expect(web.candidate).toEqual({ critical: 0, high: 1, medium: 1, exploited: 0 });
      expect(web.diff?.fixed.map((v) => v.vuln_id)).toEqual(["CVE-1"]);
      expect(sel.diffs.find((d) => d.change.name === "side")!.scan).toBeNull();
      expect(sel.pins).toHaveLength(1);
      expect(sel.pins[0]!.diff?.candidate).toEqual({ critical: 0, high: 1, medium: 1, exploited: 0 });

      const picked = (await getChartPage(db, chartId, older))!;
      expect(picked.selected?.candidate.version).toBe("1.5.0");
      expect(picked.selected?.state).toBe("none");
    });

    it("finds a workload's chart by its managed_by", async () => {
      const { chartId } = await setup();
      const ids = await chartIdsByManagedBy(db, ["HelmRelease apps/web", "HelmRelease apps/retired", "Kustomization x/y", null]);
      expect([...ids]).toEqual([["HelmRelease apps/web", chartId]]);
    });
  });
}
