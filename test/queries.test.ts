import { afterEach, describe, expect, it } from "vitest";
import type { DB } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { compareTagVersions } from "@/lib/queries/common";
import { getCvePage } from "@/lib/queries/cve";
import { getImagePage } from "@/lib/queries/image";
import { getOverview } from "@/lib/queries/overview";
import { getScanPage } from "@/lib/queries/scan";
import { getStatusPage, imageRefTag, sameVersion } from "@/lib/queries/status";
import type { ScanStatus } from "@/lib/db/schema";
import type { Severity } from "@/lib/config";
import type { Finding } from "@/lib/trivy/finding";
import { freshDb, testDatabases } from "./helpers";

const T = "2026-11-01T00:00:00.000Z";
const f = (vulnId: string, pkg: string, severity: Severity, fixedVersion: string | null = null): Finding => ({
  vulnId,
  package: pkg,
  installedVersion: "1",
  fixedVersion,
  severity,
  score: null,
  title: null,
  link: null,
});

async function digest(db: DB, imageId: number, name: string, findings: Finding[], source: "operator" | "candidate" = "operator") {
  const scan = { digest: name, osFamily: null, osName: null, scannedAt: T, reportUpdatedAt: null, scannerVersion: null, findings };
  return (await storeDigest(db, imageId, source, scan, ["CRITICAL", "HIGH", "MEDIUM"])).digestId;
}

async function workload(db: DB, imageId: number, digestId: number | null, name: string, opts: { ns?: string; tag?: string | null; gone?: boolean } = {}) {
  await db
    .insertInto("workloads")
    .values({
      namespace: opts.ns ?? "ns1",
      kind: "Deployment",
      name,
      container: "app",
      image_id: imageId,
      tag: opts.tag === undefined ? "1.0" : opts.tag,
      digest_id: digestId,
      last_seen_at: T,
      gone_at: opts.gone ? T : null,
    })
    .execute();
}

async function tag(db: DB, imageId: number, name: string, digestName: string | null, candidate = true, reason = "r") {
  await db
    .insertInto("tags")
    .values({ image_id: imageId, tag: name, digest: digestName, first_seen_at: T, is_candidate: candidate ? 1 : 0, reason })
    .execute();
}

async function scan(db: DB, imageId: number, tagName: string, digestName: string, status: ScanStatus, result: number | null = null) {
  return (
    await db
      .insertInto("scans")
      .values({
        image_id: imageId,
        tag: tagName,
        digest: digestName,
        status,
        requested_by: "t",
        requested_at: T,
        started_at: null,
        finished_at: null,
        job_name: null,
        error: null,
        result_digest_id: result,
      })
      .returning("id")
      .executeTakeFirstOrThrow()
  ).id;
}

describe("compareTagVersions", () => {
  it("compares numeric runs as integers", () => {
    expect(compareTagVersions("1.10.0", "1.9.0")).toBeGreaterThan(0);
    expect(compareTagVersions("4.0.15.2941-ls290", "4.0.15.2941-ls291")).toBeLessThan(0);
    expect(compareTagVersions("1.2.3", "1.2.3")).toBe(0);
    expect(compareTagVersions("1.2.3.1", "1.2.3")).toBeGreaterThan(0);
  });
});

describe("imageRefTag", () => {
  it("reads the tag, not a registry port", () => {
    expect(imageRefTag("mirror.gcr.io/aquasec/trivy:0.76.1")).toBe("0.76.1");
    expect(imageRefTag("localhost:5000/aquasec/trivy")).toBeNull();
    expect(imageRefTag("localhost:5000/trivy:0.1@sha256:abc")).toBe("0.1");
    expect(sameVersion("v0.76.1", "0.76.1")).toBe(true);
    expect(sameVersion("0.76.2", "0.76.1")).toBe(false);
  });
});

for (const { name, url } of testDatabases()) {
  describe(`queries (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("overview counts each CVE once per image, at its worst severity, over the running digests", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const d1 = await digest(db, img, "sha256:1", [f("CVE-1", "x", "HIGH"), f("CVE-2", "x", "MEDIUM"), f("CVE-2", "y", "MEDIUM")]);
      const d2 = await digest(db, img, "sha256:2", [f("CVE-1", "x", "CRITICAL"), f("CVE-3", "z", "MEDIUM")]);
      const stale = await digest(db, img, "sha256:old", [f("CVE-9", "x", "CRITICAL")]);
      await workload(db, img, d1, "w1", { tag: "1.0" });
      await workload(db, img, d2, "w2", { tag: "1.1", ns: "ns2" });
      await workload(db, img, stale, "w3", { tag: "0.9", gone: true });

      const { rows, totals, namespaces } = await getOverview(db);
      expect(rows).toHaveLength(1);
      const r = rows[0]!;
      // CVE-1 once, as CRITICAL; CVE-2 once despite two packages; CVE-3. CVE-9 only in a gone workload.
      expect([r.critical, r.high, r.medium]).toEqual([1, 0, 2]);
      expect(typeof r.critical).toBe("number");
      expect(r.tags).toEqual(["1.0", "1.1"]);
      expect(r.workloads).toBe(2);
      expect(r.digests).toBe(2);
      expect(totals).toMatchObject({ images: 1, workloads: 2, critical: 1, high: 0, medium: 2 });
      expect(namespaces).toEqual(["ns1", "ns2"]);
    });

    it("overview says whether tag discovery has checked each image", async () => {
      db = await freshDb(url);
      const unchecked = await upsertImage(db, "ghcr.io", "a/unchecked");
      const current = await upsertImage(db, "ghcr.io", "a/current");
      const floating = await upsertImage(db, "ghcr.io", "a/floating");
      const failed = await upsertImage(db, "ghcr.io", "a/failed");
      const pinned = await upsertImage(db, "ghcr.io", "a/pinned");
      for (const [img, tag] of [[unchecked, "1.0"], [current, "1.0"], [floating, "latest"], [failed, "1.0"], [pinned, null]] as const) {
        await workload(db, img, await digest(db, img, `sha256:${img}`, []), `w${img}`, { tag });
      }
      await db.updateTable("images").set({ last_tag_sync_at: "2026-11-12T00:00:00.000Z" }).where("id", "in", [current, floating, failed]).execute();
      await db.updateTable("images").set({ tag_sync_error: "429 Too Many Requests" }).where("id", "=", failed).execute();

      const { rows, totals } = await getOverview(db, { sort: "image" });
      expect(Object.fromEntries(rows.map((r) => [r.repository, r.tagCheck]))).toEqual({
        "a/current": { checkedAt: "2026-11-12T00:00:00.000Z", error: null, pinned: false, floating: false },
        "a/failed": { checkedAt: "2026-11-12T00:00:00.000Z", error: "429 Too Many Requests", pinned: false, floating: false },
        "a/floating": { checkedAt: "2026-11-12T00:00:00.000Z", error: null, pinned: false, floating: true },
        "a/pinned": { checkedAt: null, error: null, pinned: true, floating: false },
        "a/unchecked": { checkedAt: null, error: null, pinned: false, floating: false },
      });
      expect(totals.tagsChecked).toBe(3);
    });

    it("image page counts the running image and each scanned candidate the same way", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const run = await digest(db, img, "sha256:run", [f("CVE-1", "x", "HIGH"), f("CVE-1", "y", "CRITICAL"), f("CVE-2", "x", "MEDIUM")]);
      const cand = await digest(db, img, "sha256:cand", [f("CVE-2", "x", "MEDIUM"), f("CVE-3", "x", "HIGH"), f("CVE-3", "y", "HIGH")], "candidate");
      await workload(db, img, run, "w1", { tag: "1.0" });
      await tag(db, img, "1.1", "sha256:cand");
      await tag(db, img, "1.2", "sha256:unscanned");
      await scan(db, img, "1.1", "sha256:cand", "done", cand);

      const page = (await getImagePage(db, img))!;
      // CVE-1 once, as CRITICAL; CVE-3 once despite two packages.
      expect(page.runningCounts).toEqual({ critical: 1, high: 0, medium: 1 });
      expect(Object.fromEntries(page.tags.map((t) => [t.tag, t.counts]))).toEqual({
        "1.1": { critical: 0, high: 1, medium: 1 },
        "1.2": null,
      });
    });

    it("the namespace filter narrows the digests that count", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const d1 = await digest(db, img, "sha256:1", [f("CVE-1", "x", "HIGH")]);
      const d2 = await digest(db, img, "sha256:2", [f("CVE-1", "x", "CRITICAL"), f("CVE-3", "z", "MEDIUM")]);
      await workload(db, img, d1, "w1");
      await workload(db, img, d2, "w2", { ns: "ns2" });

      const { rows, namespaces } = await getOverview(db, { namespace: "ns1" });
      expect([rows[0]!.critical, rows[0]!.high, rows[0]!.medium, rows[0]!.workloads]).toEqual([0, 1, 0, 1]);
      expect(namespaces).toEqual(["ns1", "ns2"]);
    });

    it("omits images with only gone workloads", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      await workload(db, img, await digest(db, img, "sha256:1", [f("CVE-1", "x", "HIGH")]), "w1", { gone: true });
      expect((await getOverview(db)).rows).toEqual([]);
    });

    it("lists a workload that has no report yet, with zero counts", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      await workload(db, img, null, "w1");
      const r = (await getOverview(db)).rows[0]!;
      expect([r.workloads, r.critical, r.digests]).toEqual([1, 0, 0]);
    });

    it("picks the newest candidate numerically and summarises its done scan", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const run = await digest(db, img, "sha256:run", [f("CVE-1", "x", "HIGH", "2"), f("CVE-2", "x", "HIGH"), f("CVE-4", "x", "HIGH")]);
      const cand = await digest(db, img, "sha256:c10", [f("CVE-2", "x", "HIGH"), f("CVE-3", "x", "HIGH")], "candidate");
      await workload(db, img, run, "w1");
      await tag(db, img, "1.9.0", "sha256:c9");
      await tag(db, img, "1.10.0", "sha256:c10");
      await tag(db, img, "9.9.9-debian", "sha256:other", false);
      const scanId = await scan(db, img, "1.10.0", "sha256:c10", "done", cand);

      const r = (await getOverview(db)).rows[0]!;
      expect(r.candidateCount).toBe(2);
      expect(r.candidate?.tag).toBe("1.10.0");
      expect(r.candidate?.scan?.id).toBe(scanId);
      expect(r.candidate?.scan?.diff?.summary).toBe("fixes 2, leaves 1, adds 1");
    });

    it("applies severity and candidate filters and sorts", async () => {
      db = await freshDb(url);
      const a = await upsertImage(db, "ghcr.io", "a");
      const b = await upsertImage(db, "ghcr.io", "b");
      const c = await upsertImage(db, "ghcr.io", "c");
      await workload(db, a, await digest(db, a, "sha256:a", [f("C1", "x", "CRITICAL")]), "a");
      await workload(db, b, await digest(db, b, "sha256:b", [f("H1", "x", "HIGH"), f("H2", "x", "HIGH")]), "b");
      await workload(db, c, await digest(db, c, "sha256:c", [f("M1", "x", "MEDIUM")]), "c");
      await tag(db, c, "2.0", "sha256:c2");

      const repos = async (o: Parameters<typeof getOverview>[1]) => (await getOverview(db, o)).rows.map((r) => r.repository);
      expect(await repos({})).toEqual(["a", "b", "c"]);
      expect(await repos({ minSeverity: "CRITICAL" })).toEqual(["a"]);
      expect(await repos({ minSeverity: "HIGH" })).toEqual(["a", "b"]);
      expect(await repos({ minSeverity: "MEDIUM" })).toEqual(["a", "b", "c"]);
      expect(await repos({ needs: ["candidate"] })).toEqual(["c"]);
      // b runs an older build of its tag; a has a known-exploited CVE.
      await db.updateTable("workloads").set({ pod_digest: "sha256:old" }).where("image_id", "=", b).execute();
      await db.insertInto("kev").values({ cve_id: "C1", vulnerability_name: null, vendor_project: null, product: null, date_added: "2026-01-01", due_date: null, known_ransomware: 0, short_description: null }).execute();
      expect(await repos({ needs: ["stale"] })).toEqual(["b"]);
      expect(await repos({ needs: ["candidate", "stale"] })).toEqual(["b", "c"]);
      expect(await repos({ exploited: true })).toEqual(["a"]);
      expect(await repos({ needs: ["candidate", "stale"], exploited: true })).toEqual([]);
      expect(await repos({ sort: "high" })).toEqual(["b", "a", "c"]);
      expect(await repos({ sort: "image", dir: "desc" })).toEqual(["c", "b", "a"]);
    });

    it("the CVE page shows affected images, their live workloads, and which candidates fix it", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const run = await digest(db, img, "sha256:run", [f("CVE-1", "x", "HIGH", "2"), f("CVE-2", "x", "HIGH")]);
      const fixes = await digest(db, img, "sha256:fix", [f("CVE-2", "x", "HIGH")], "candidate");
      const keeps = await digest(db, img, "sha256:keep", [f("CVE-1", "x", "HIGH", "2")], "candidate");
      await workload(db, img, run, "live");
      await workload(db, img, run, "old", { gone: true });
      await scan(db, img, "1.1", "sha256:fix", "done", fixes);
      await scan(db, img, "1.2", "sha256:keep", "done", keeps);
      await scan(db, img, "1.3", "sha256:pending", "queued");

      const page = await getCvePage(db, "CVE-1");
      expect(page.severity).toBe("HIGH");
      expect(page.affected).toHaveLength(1);
      const a = page.affected[0]!;
      expect(a.findings.map((x) => [x.package, x.fixedVersion])).toEqual([["x", "2"]]);
      expect(a.workloads.map((w) => w.name)).toEqual(["live"]);
      expect(a.candidates.map((c) => [c.tag, c.fixes])).toEqual([
        ["1.1", true],
        ["1.2", false],
      ]);
      expect(page.introducedBy).toEqual([]);
    });

    it("the CVE page separates a CVE only a candidate would introduce", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      await workload(db, img, await digest(db, img, "sha256:run", [f("CVE-1", "x", "HIGH")]), "live");
      const cand = await digest(db, img, "sha256:c", [f("CVE-NEW", "x", "HIGH")], "candidate");
      await scan(db, img, "2.0", "sha256:c", "done", cand);

      const page = await getCvePage(db, "CVE-NEW");
      expect(page.affected).toEqual([]);
      expect(page.introducedBy.map((c) => c.tag)).toEqual(["2.0"]);
      expect((await getCvePage(db, "NOPE")).severity).toBeNull();
    });

    it("the scan page diffs against the union, or one chosen running digest", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const d1 = await digest(db, img, "sha256:1", [f("CVE-1", "x", "HIGH", "2"), f("CVE-2", "x", "HIGH")]);
      const d2 = await digest(db, img, "sha256:2", [f("CVE-2", "x", "HIGH"), f("CVE-3", "x", "HIGH")]);
      await workload(db, img, d1, "w1");
      await workload(db, img, d2, "w2");
      const cand = await digest(db, img, "sha256:c", [f("CVE-1", "x", "HIGH")], "candidate");
      const id = await scan(db, img, "2.0", "sha256:c", "done", cand);

      const union = (await getScanPage(db, id))!;
      expect(union.diff!.fixed.map((v) => v.vuln_id).sort()).toEqual(["CVE-2", "CVE-3"]);
      expect(union.diff!.stillPresent.map((s) => [s.running.vuln_id, s.fixAvailableUpstream])).toEqual([["CVE-1", true]]);

      const one = (await getScanPage(db, id, d2))!;
      expect(one.comparedWith.map((d) => d.id)).toEqual([d2]);
      expect(one.diff!.introduced.map((v) => v.vuln_id)).toEqual(["CVE-1"]);

      const queued = await scan(db, img, "3.0", "sha256:q", "queued");
      expect((await getScanPage(db, queued))!.diff).toBeNull();
      expect(await getScanPage(db, 999999)).toBeNull();
    });

    it("the image page merges findings across digests and attaches scans to tags", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const d1 = await digest(db, img, "sha256:1", [f("CVE-1", "x", "HIGH"), f("CVE-2", "x", "CRITICAL")]);
      const d2 = await digest(db, img, "sha256:2", [f("CVE-1", "x", "HIGH")]);
      await workload(db, img, d1, "w1");
      await workload(db, img, d2, "w2", { tag: null });
      await workload(db, img, d2, "w0", { gone: true });
      await tag(db, img, "2.0", "sha256:c");
      await tag(db, img, "9.0", null, false);
      const id = await scan(db, img, "2.0", "sha256:c", "failed");

      const p = (await getImagePage(db, img))!;
      expect(p.vulns.map((v) => [v.vuln_id, v.digestIds.length])).toEqual([
        ["CVE-2", 1],
        ["CVE-1", 2],
      ]);
      expect(p.cveCount).toBe(2);
      expect(p.workloads.map((w) => w.name)).toEqual(["w1", "w2", "w0"]);
      expect(p.pinnedByDigest).toBe(false);
      expect(p.tags.map((t) => [t.tag, t.scan?.id ?? null])).toEqual([
        ["2.0", id],
        ["9.0", null],
      ]);
      expect(await getImagePage(db, 999999)).toBeNull();
    });

    it("the status page returns runs, the queue, and tag errors", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "ghcr.io", "a/b");
      await db.updateTable("images").set({ tag_sync_error: "401" }).where("id", "=", img).execute();
      await db.insertInto("sync_runs").values({ name: "tag_sync", started_at: T, finished_at: T, ok: 0, error: "x", detail: null }).execute();
      await scan(db, img, "1", "sha256:q", "queued");
      await scan(db, img, "2", "sha256:f", "failed");
      await scan(db, img, "3", "sha256:d", "done");

      const s = await getStatusPage(db);
      expect(s.runs.tag_sync).toHaveLength(1);
      expect(s.runs.report_sync).toEqual([]);
      expect(s.active.map((x) => [x.tag, x.repository])).toEqual([["1", "a/b"]]);
      expect(s.failed.map((x) => x.tag)).toEqual(["2"]);
      expect(s.tagSyncErrors.map((i) => i.id)).toEqual([img]);
      expect(s.trivyServerVersion).toBeNull();
    });
  });
}
