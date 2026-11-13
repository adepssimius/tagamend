import { afterEach, describe, expect, it } from "vitest";
import { type DB, now } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { fluxManager } from "@/lib/k8s/report-sync";
import { getOverview } from "@/lib/queries/overview";
import { getSettings, setSettings } from "@/lib/settings";
import { freshDb, testDatabases } from "./helpers";

describe("fluxManager", () => {
  const inv = new Map([["media/Deployment/seerr", "flux-system/apps-media"]]);
  it("prefers a Kustomization inventory, then helm-controller and kustomize labels", () => {
    expect(fluxManager("media", { kind: "Deployment", name: "seerr", labels: {} }, inv)).toBe("Kustomization flux-system/apps-media");
    expect(
      fluxManager("rook", { kind: "CephCluster", name: "c", labels: { "helm.toolkit.fluxcd.io/name": "rook-cluster", "helm.toolkit.fluxcd.io/namespace": "rook" } }, inv),
    ).toBe("HelmRelease rook/rook-cluster");
    expect(fluxManager("x", { kind: "Deployment", name: "y", labels: { "kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "flux-system" } }, inv)).toBe(
      "Kustomization flux-system/apps",
    );
  });
  it("says none only when it could look, and unknown otherwise", () => {
    expect(fluxManager("tidyarr-dev", { kind: "Deployment", name: "seerr", labels: {} }, inv)).toBe("none");
    expect(fluxManager("x", { kind: "Driver", name: "d", labels: null }, inv)).toBeNull();
    expect(fluxManager("x", { kind: "Deployment", name: "d", labels: {} }, null)).toBeNull();
  });
});

for (const { name, url } of testDatabases()) {
  describe(`Flux scope (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("leaves out workloads known not to be Flux's, by default, and keeps unknown ones", async () => {
      db = await freshDb(url);
      expect((await getSettings(db)).fluxManagedOnly).toBe(true);
      for (const [repo, managed] of [["a/flux", "Kustomization flux-system/apps"], ["a/hand", "none"], ["a/unknown", null]] as const) {
        const img = await upsertImage(db, "ghcr.io", repo);
        const { digestId } = await storeDigest(db, img, "operator", { digest: `sha256:${repo}`, osFamily: null, osName: null, scannedAt: now(), reportUpdatedAt: null, scannerVersion: null, findings: [] }, ["HIGH"]);
        await db.insertInto("workloads").values({ namespace: "n", kind: "Deployment", name: repo, container: "c", image_id: img, tag: "1", digest_id: digestId, last_seen_at: now(), managed_by: managed, gone_at: null }).execute();
      }
      const repos = async () => (await getOverview(db, { sort: "image" })).rows.map((r) => r.repository);
      expect(await repos()).toEqual(["a/flux", "a/unknown"]);
      await setSettings(db, { autoScanBestCandidate: false, autoScanRunningBuild: false, fluxManagedOnly: false });
      expect(await repos()).toEqual(["a/flux", "a/hand", "a/unknown"]);
    });
  });
}
