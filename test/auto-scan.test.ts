import { afterEach, describe, expect, it } from "vitest";
import { getConfig } from "@/lib/config";
import { type DB, now } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { log } from "@/lib/log";
import { AUTO_REQUESTER, autoScan } from "@/lib/scan/auto";
import { setSettings } from "@/lib/settings";
import { freshDb, testDatabases } from "./helpers";

for (const { name, url } of testDatabases()) {
  describe(`auto scan (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("does nothing until turned on, then queues each best candidate and stale build once", async () => {
      db = await freshDb(url);
      const ctx = { db, config: getConfig({ DATABASE_URL: ":memory:" }), log, signal: new AbortController().signal };
      const img = await upsertImage(db, "ghcr.io", "a/b");
      const { digestId } = await storeDigest(db, img, "operator", { digest: "sha256:run", osFamily: null, osName: null, scannedAt: now(), reportUpdatedAt: null, scannerVersion: null, findings: [] }, ["HIGH"]);
      await db.insertInto("workloads").values({ namespace: "n", kind: "Deployment", name: "w", container: "c", image_id: img, tag: "1.0", digest_id: digestId, last_seen_at: now(), report_digest: "sha256:run", pod_digest: "sha256:pod", gone_at: null }).execute();
      for (const [tag, digest] of [["1.1", "sha256:c11"], ["1.2", "sha256:c12"], ["1.3", null]] as const) {
        await db.insertInto("tags").values({ image_id: img, tag, digest, first_seen_at: now(), is_candidate: 1, reason: "r" }).execute();
      }

      expect(await autoScan(ctx)).toEqual({ idle: true, disabled: true });

      await setSettings(db, { autoScanBestCandidate: true, autoScanRunningBuild: false, fluxManagedOnly: true });
      // The best candidate is 1.3, but it has no digest, so nothing is queued for it.
      expect(await autoScan(ctx)).toEqual({ idle: true });
      await db.updateTable("tags").set({ is_candidate: 0 }).where("tag", "=", "1.3").execute();
      expect(await autoScan(ctx)).toEqual({ queued: 1 });

      await setSettings(db, { autoScanBestCandidate: true, autoScanRunningBuild: true, fluxManagedOnly: true });
      expect(await autoScan(ctx)).toEqual({ queued: 1 });
      expect(await autoScan(ctx)).toEqual({ idle: true });

      const scans = await db.selectFrom("scans").select(["tag", "digest", "requested_by"]).orderBy("id").execute();
      expect(scans).toEqual([
        { tag: "1.2", digest: "sha256:c12", requested_by: AUTO_REQUESTER },
        { tag: "1.0", digest: "sha256:pod", requested_by: AUTO_REQUESTER },
      ]);

      // A failed scan is not retried automatically.
      await db.updateTable("scans").set({ status: "failed" }).execute();
      expect(await autoScan(ctx)).toEqual({ idle: true });
    });
  });
}
