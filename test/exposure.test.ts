import { afterEach, describe, expect, it } from "vitest";
import { getConfig } from "@/lib/config";
import { type DB, now } from "@/lib/db";
import { storeDigest, upsertImage } from "@/lib/db/store";
import { exposureOf, hostMatches, oidcRedirectHosts, type Route } from "@/lib/exposure/classify";
import { type ExposureSource, syncExposure } from "@/lib/exposure/sync";
import { log } from "@/lib/log";
import { setSettings } from "@/lib/settings";
import { freshDb, testDatabases } from "./helpers";

describe("exposure classification", () => {
  it("matches host patterns by DNS labels", () => {
    expect(hostMatches("app.admin.example.com", "*.admin.example.com")).toBe(true);
    expect(hostMatches("a.b.admin.example.com", "*.admin.example.com")).toBe(true);
    expect(hostMatches("admin.example.com", "*.admin.example.com")).toBe(false);
    expect(hostMatches("App.Example.com", "app.example.com")).toBe(true);
    expect(hostMatches("appXexample.com", "app.example.com")).toBe(false);
  });

  it("reads redirect URI hosts from block and flow lists", () => {
    const config = `identity_providers:
  oidc:
    clients:
      - client_id: 'books'
        redirect_uris:
          - 'https://books.example.com/auth/callback'
          - "https://books.example.com/other"
        scopes: [openid]
      - client_id: x
        redirect_uris: ['https://x.example.com/cb', https://y.example.com/cb]
      - client_id: local
        redirect_uris:
        - http://localhost:3000/cb
`;
    expect([...oidcRedirectHosts(config)].sort()).toEqual(["books.example.com", "localhost", "x.example.com", "y.example.com"]);
  });

  it("summarises a workload as its worst route", () => {
    const r = (reach: Route["reach"], auth: Route["auth"]): Route => ({ via: "ingress", address: "a", object: "o", reach, auth });
    expect(exposureOf([])).toBe("none");
    expect(exposureOf([r("lan", "app"), r("internet", "forward-auth")])).toBe("internet-forward-auth");
    expect(exposureOf([r("internet", "oidc"), r("internet", "app")])).toBe("internet-app");
    expect(exposureOf([r("tailnet", "app"), r("lan", "app")])).toBe("tailnet");
  });
});

const fake = (oidcConfig: string): ExposureSource => ({
  owners: {
    async getObject(ref) {
      if (ref.kind === "ReplicaSet") {
        return { metadata: { name: ref.name, ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name: ref.name.replace(/-[a-z0-9]+$/, ""), controller: true }] } };
      }
      return { metadata: { name: ref.name } };
    },
  },
  async listPods() {
    return [
      { namespace: "m", name: "books-abc-1", labels: { app: "books" }, controller: { kind: "ReplicaSet", name: "books-abc" } },
      { namespace: "m", name: "media-abc-1", labels: { app: "media" }, controller: { kind: "ReplicaSet", name: "media-abc" } },
      { namespace: "m", name: "admin-abc-1", labels: { app: "admin" }, controller: { kind: "ReplicaSet", name: "admin-abc" } },
      { namespace: "m", name: "sync-abc-1", labels: { app: "sync" }, controller: { kind: "ReplicaSet", name: "sync-abc" } },
    ];
  },
  async listServices() {
    const svc = (name: string, type = "ClusterIP", extra = {}) => ({ namespace: "m", name, type, selector: { app: name }, loadBalancerClass: null, annotations: {}, addresses: [], ports: [{ port: 80 }], ...extra });
    return [svc("books"), svc("media"), svc("admin"), svc("sync", "LoadBalancer", { addresses: ["10.0.0.5"] })];
  },
  async listIngresses() {
    const ing = (name: string, host: string, annotations = {}) => ({ namespace: "m", name, className: "nginx", annotations, rules: [{ host, paths: [{ path: "/", service: name }] }], defaultService: null });
    return [
      ing("books", "books.example.com"),
      ing("media", "media.example.com"),
      ing("admin", "admin.int.example.com", { "nginx.ingress.kubernetes.io/auth-url": "http://auth.svc.local/api/verify" }),
    ];
  },
  async listIngressClasses() {
    return { controllers: new Map([["nginx", "k8s.io/ingress-nginx"]]), defaultClass: null };
  },
  async readConfigMap() {
    return oidcConfig;
  },
});

for (const { name, url } of testDatabases()) {
  describe(`exposure sync (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("follows Ingress to Service to pods to workload, and classifies by the settings", async () => {
      db = await freshDb(url);
      const ctx = { db, config: getConfig({ DATABASE_URL: ":memory:" }), log, signal: new AbortController().signal };
      const img = await upsertImage(db, "ghcr.io", "x/y");
      const { digestId } = await storeDigest(db, img, "operator", { digest: "sha256:d", osFamily: null, osName: null, scannedAt: now(), reportUpdatedAt: null, scannerVersion: null, findings: [] }, ["HIGH"]);
      for (const n of ["books", "media", "admin", "sync", "batch"]) {
        await db.insertInto("workloads").values({ namespace: "m", kind: "Deployment", name: n, container: "c", image_id: img, tag: "1", digest_id: digestId, last_seen_at: now(), gone_at: null }).execute();
      }
      await setSettings(db, { internalHostPatterns: ["*.int.example.com"], oidcClientsSource: "iam/auth/config.yml" });

      await syncExposure(ctx, { source: fake("redirect_uris:\n  - https://books.example.com/cb\n") });
      const rows = await db.selectFrom("workloads").select(["name", "exposure_summary", "exposure"]).orderBy("name").execute();
      expect(Object.fromEntries(rows.map((r) => [r.name, r.exposure_summary]))).toEqual({
        admin: "lan",
        batch: "none",
        books: "internet-oidc",
        media: "internet-app",
        sync: "lan",
      });
      const admin = JSON.parse(rows.find((r) => r.name === "admin")!.exposure!) as Route[];
      expect(admin).toEqual([{ via: "ingress", address: "admin.int.example.com", object: "Ingress m/admin", reach: "lan", auth: "forward-auth", authBy: "auth.svc.local" }]);

      // With no internal patterns, the admin host counts as the internet (behind forward auth).
      await setSettings(db, { internalHostPatterns: [], loadBalancerReach: "internet" });
      await syncExposure(ctx, { source: fake("") });
      const after = await db.selectFrom("workloads").select(["name", "exposure_summary"]).orderBy("name").execute();
      expect(Object.fromEntries(after.map((r) => [r.name, r.exposure_summary]))).toMatchObject({
        admin: "internet-forward-auth",
        books: "internet-app",
        sync: "internet-app",
      });
    });
  });
}
