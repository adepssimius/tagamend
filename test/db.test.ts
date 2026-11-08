import { afterEach, describe, expect, it } from "vitest";
import type { DB } from "@/lib/db";
import { storeDigest, upsertImage, withSyncRun } from "@/lib/db/store";
import type { DigestScan, Finding } from "@/lib/trivy/finding";
import { freshDb, testDatabases } from "./helpers";

const finding = (over: Partial<Finding> = {}): Finding => ({
  vulnId: "CVE-2024-0001",
  package: "openssl",
  installedVersion: "3.0.1",
  fixedVersion: "3.0.2",
  severity: "HIGH",
  score: 7.5,
  title: "t",
  link: null,
  ...over,
});

const scan = (findings: Finding[], reportUpdatedAt: string | null = "2026-11-01T00:00:00Z"): DigestScan => ({
  digest: "sha256:aaa",
  osFamily: "debian",
  osName: "12",
  scannedAt: "2026-11-01T00:00:00Z",
  reportUpdatedAt,
  scannerVersion: "0.76.1",
  findings,
});

for (const { name, url } of testDatabases()) {
  describe(`store (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("upserts images idempotently", async () => {
      db = await freshDb(url);
      const a = await upsertImage(db, "ghcr.io", "x/y");
      const b = await upsertImage(db, "ghcr.io", "x/y");
      expect(a).toBe(b);
    });

    it("filters severities, dedupes, counts, and skips older reports", async () => {
      db = await freshDb(url);
      const img = await upsertImage(db, "index.docker.io", "library/nginx");
      const first = await storeDigest(
        db,
        img,
        "operator",
        scan([finding(), finding(), finding({ vulnId: "CVE-2", severity: "LOW" }), finding({ vulnId: "CVE-3", severity: "CRITICAL" })]),
        ["CRITICAL", "HIGH", "MEDIUM"],
      );
      expect(first.changed).toBe(true);
      const row = await db.selectFrom("image_digests").selectAll().where("id", "=", first.digestId).executeTakeFirstOrThrow();
      expect([row.critical, row.high, row.low]).toEqual([1, 1, 0]);
      const vulns = await db.selectFrom("vulnerabilities").selectAll().where("digest_id", "=", first.digestId).execute();
      expect(vulns).toHaveLength(2);

      const same = await storeDigest(db, img, "operator", scan([]), ["HIGH"]);
      expect(same).toEqual({ digestId: first.digestId, changed: false });

      const newer = await storeDigest(db, img, "operator", scan([], "2026-11-02T00:00:00Z"), ["HIGH"]);
      expect(newer.changed).toBe(true);
      expect(await db.selectFrom("vulnerabilities").selectAll().execute()).toHaveLength(0);
    });

    it("records sync runs, including failures", async () => {
      db = await freshDb(url);
      await withSyncRun(db, "report_sync", async () => ({ n: 1 }));
      await expect(withSyncRun(db, "tag_sync", async () => { throw new Error("boom"); })).rejects.toThrow("boom");
      const runs = await db.selectFrom("sync_runs").selectAll().orderBy("id").execute();
      expect(runs.map((r) => [r.name, r.ok, r.error])).toEqual([
        ["report_sync", 1, null],
        ["tag_sync", 0, "boom"],
      ]);
    });
  });
}
