import { afterEach, describe, expect, it } from "vitest";
import { getConfig } from "@/lib/config";
import type { DB } from "@/lib/db";
import { getKv, storeDigest } from "@/lib/db/store";
import { syncReports } from "@/lib/k8s/report-sync";
import { KV } from "@/lib/kv-keys";
import type { Log } from "@/lib/log";
import type { WorkerContext } from "@/lib/worker-context";
import { freshDb, testDatabases } from "./helpers";
import { FakeSource, fixtureOwners, fixtureReports, reportNamed, type RawReport } from "./report-fixtures";

function context(db: DB, signal = new AbortController().signal) {
  const warnings: { msg: string; fields?: Record<string, unknown> }[] = [];
  const log: Log = {
    debug: () => {},
    info: () => {},
    warn: (msg, fields) => void warnings.push({ msg, fields }),
    error: (msg, fields) => void warnings.push({ msg, fields }),
  };
  const config = getConfig({ DATABASE_URL: ":memory:", SEVERITIES: "CRITICAL,HIGH,MEDIUM" });
  const ctx: WorkerContext = { db, config, log, signal };
  return { ctx, warnings };
}

const at = (iso: string) => () => new Date(iso);

/** An extra report and ReplicaSet for a rollout's leftover, scaled to zero. */
function staleReplicaSet(reports: RawReport[]) {
  const r = structuredClone(reportNamed(reports, "replicaset-demo-api-7c4967f8db-demo-api"));
  r.metadata.name = "replicaset-demo-api-55f6b8d9c7-demo-api";
  r.metadata.labels["trivy-operator.resource.name"] = "demo-api-55f6b8d9c7";
  r.report.artifact.digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
  const rs = {
    apiVersion: "apps/v1",
    kind: "ReplicaSet",
    metadata: {
      name: "demo-api-55f6b8d9c7",
      namespace: "team-a",
      ownerReferences: [{ apiVersion: "apps/v1", kind: "Deployment", name: "demo-api", controller: true }],
    },
    spec: { replicas: 0 },
  };
  return { report: r, rs };
}

async function workloads(db: DB) {
  return db
    .selectFrom("workloads")
    .innerJoin("images", "images.id", "workloads.image_id")
    .leftJoin("image_digests", "image_digests.id", "workloads.digest_id")
    .select([
      "workloads.namespace",
      "workloads.kind",
      "workloads.name",
      "workloads.container",
      "images.registry",
      "images.repository",
      "workloads.tag",
      "image_digests.digest",
      "workloads.last_seen_at",
      "workloads.gone_at",
    ])
    .orderBy("workloads.namespace")
    .orderBy("workloads.name")
    .execute();
}

for (const { name, url } of testDatabases()) {
  describe(`report sync (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("stores captured reports and resolves each workload to its top-level owner", async () => {
      db = await freshDb(url);
      const reports = fixtureReports();
      const stale = staleReplicaSet(reports);
      const invalid = structuredClone(reportNamed(reports, "replicaset-demo-web-5c558b58bf-demo-web"));
      invalid.metadata.name = "broken";
      delete (invalid.report as { artifact?: unknown }).artifact;
      const source = new FakeSource([...reports, stale.report, invalid], [...fixtureOwners(), stale.rs]);
      const { ctx, warnings } = context(db);

      const detail = await syncReports(ctx, { source, clock: at("2026-11-08T12:00:00Z"), pageSize: 4 });

      expect(detail).toMatchObject({
        reports: 12,
        changedDigests: 10,
        skipped: 1,
        skippedReasons: { scaled_to_zero: 1 },
        invalid: 1,
        workloads: 10,
        markedGone: 0,
        ownerLookupErrors: 0,
        pages: 3,
      });
      expect(source.pageRequests).toBe(3);
      expect(warnings.map((w) => w.fields?.report)).toEqual(["team-b/broken"]);

      const rows = await workloads(db);
      expect(rows.map((r) => [r.namespace, r.kind, r.name, r.container])).toEqual([
        ["kube-system", "DaemonSet", "demo-node-agent", "node-agent"],
        ["team-a", "Deployment", "demo-api", "demo-api"],
        ["team-b", "Deployment", "demo-indexer", "demo-indexer"],
        ["team-b", "Deployment", "demo-web", "demo-web"],
        ["team-c", "Job", "demo-db-init", "psql"],
        ["team-c", "Cluster", "demo-postgres", "postgres"],
        ["team-d", "CronJob", "demo-health-check", "demo-health-check"],
        ["team-e", "AdvancedCronJob", "demo-collector", "collector"],
        ["team-e", "Prometheus", "prometheus-prometheus", "config-reloader"],
        ["trivy-system", "StatefulSet", "trivy-server", "trivy-server"],
      ]);
      const api = rows.find((r) => r.name === "demo-api")!;
      expect(api).toMatchObject({
        registry: "ghcr.io",
        repository: "example/demo-api",
        tag: "latest",
        digest: "sha256:23f03846bdc538562a26ad33e2183876d8b9f7fdb7bee63d4a5969c1bc6ce5bc",
        last_seen_at: "2026-11-08T12:00:00.000Z",
        gone_at: null,
      });
      expect(new Set(rows.map((r) => r.registry))).toEqual(
        new Set(["ghcr.io", "index.docker.io", "lscr.io", "quay.io", "mirror.gcr.io"]),
      );

      // UNKNOWN findings are dropped by SEVERITIES; demo-api has one each of
      // HIGH, MEDIUM and UNKNOWN.
      const digest = await db
        .selectFrom("image_digests")
        .selectAll()
        .where("digest", "=", api.digest!)
        .executeTakeFirstOrThrow();
      expect([digest.critical, digest.high, digest.medium, digest.unknown, digest.source]).toEqual([0, 1, 1, 0, "operator"]);
      expect(digest.report_updated_at).toBe("2026-11-07T19:13:37.000Z");

      // The newest report is the collector's (2026-11-08T14:32:07Z).
      expect(await getKv(db, KV.trivyReportVersion)).toBe("0.76.1");
    });

    it("caches owner lookups for one sync", async () => {
      db = await freshDb(url);
      const reports = fixtureReports();
      // A second container in the same Pod, and a second CNPG instance.
      const sidecar = structuredClone(reportNamed(reports, "pod-demo-postgres-1-postgres"));
      sidecar.metadata.labels["trivy-operator.container.name"] = "bootstrap-controller";
      const replica = structuredClone(reportNamed(reports, "pod-demo-postgres-1-postgres"));
      replica.metadata.labels["trivy-operator.resource.name"] = "demo-postgres-9";
      const pod9 = structuredClone(fixtureOwners().find((o) => o.metadata?.name === "demo-postgres-1")!);
      pod9.metadata!.name = "demo-postgres-9";
      const source = new FakeSource([...reports, sidecar, replica], [...fixtureOwners(), pod9]);

      const detail = await syncReports(context(db).ctx, { source });

      expect(detail.workloads).toBe(11);
      // A CNPG Cluster is named from the ownerReference and never read.
      expect(source.reads.filter((k) => k.endsWith("/Cluster/team-c/demo-postgres"))).toHaveLength(0);
      expect(source.reads.filter((k) => k.endsWith("/Pod/team-c/demo-postgres-1"))).toHaveLength(1);
      expect(new Set(source.reads).size).toBe(source.reads.length);
      expect(detail.ownerReads).toBe(source.reads.length);
    });

    it("stops at the nearest existing object when an owner is missing or unreadable", async () => {
      db = await freshDb(url);
      const reports = fixtureReports();
      const owners = fixtureOwners().filter((o) => o.kind !== "Deployment");
      const source = new FakeSource(reports, owners);
      source.forbidden.add("apps.kruise.io/v1alpha1/AdvancedCronJob/team-e/demo-collector");
      // The Job behind demo-db-init has gone (ttlSecondsAfterFinished).
      source.objects.delete("batch/v1/Job/team-c/demo-db-init");
      const { ctx, warnings } = context(db);

      const detail = await syncReports(ctx, { source });

      const rows = await workloads(db);
      const byContainer = Object.fromEntries(rows.map((r) => [r.container, `${r.kind}/${r.name}`]));
      expect(byContainer).toMatchObject({
        "demo-api": "ReplicaSet/demo-api-7c4967f8db",
        // 403: the owner is still named from its ownerReference.
        collector: "AdvancedCronJob/demo-collector",
        // A custom resource is named without being read.
        postgres: "Cluster/demo-postgres",
      });
      expect(byContainer.psql).toBeUndefined();
      expect(detail).toMatchObject({ skipped: 1, skippedReasons: { resource_gone: 1 }, ownerLookupErrors: 1 });
      expect(warnings.map((w) => w.msg)).toEqual(["report sync: owner lookup failed"]);
    });

    it("notices a pod on an older build, and treats that build as running once it is scanned", async () => {
      db = await freshDb(url);
      const reports = fixtureReports();
      const source = new FakeSource(reports, fixtureOwners());
      const api = reportNamed(reports, "replicaset-demo-api-7c4967f8db-demo-api");
      const reported = api.report.artifact.digest as string;
      const older = `sha256:${"9".repeat(64)}`;
      source.podImages = [
        { namespace: "team-a", podName: "demo-api-7c4967f8db-abcde", owner: { kind: "ReplicaSet", name: "demo-api-7c4967f8db" }, container: "demo-api", digest: older },
      ];
      const { ctx } = context(db);

      const first = await syncReports(ctx, { source });
      expect(first.staleBuilds).toBe(1);
      const row = async () =>
        db
          .selectFrom("workloads")
          .innerJoin("image_digests", "image_digests.id", "workloads.digest_id")
          .select(["workloads.pod_digest", "workloads.report_digest", "image_digests.digest as running"])
          .where("workloads.name", "=", "demo-api")
          .executeTakeFirstOrThrow();
      // Not scanned yet: the CVEs shown are still the report's.
      expect(await row()).toEqual({ pod_digest: older, report_digest: reported, running: reported });

      const imageId = (await db.selectFrom("workloads").select("image_id").where("name", "=", "demo-api").executeTakeFirstOrThrow()).image_id;
      await storeDigest(db, imageId, "candidate", { digest: older, osFamily: null, osName: null, scannedAt: "2026-11-01T00:00:00Z", reportUpdatedAt: null, scannerVersion: null, findings: [] }, ["HIGH"]);
      await syncReports(ctx, { source });
      expect(await row()).toEqual({ pod_digest: older, report_digest: reported, running: older });

      // Pod restarted onto the reported build: no longer stale.
      source.podImages = [{ ...source.podImages[0]!, digest: reported }];
      const after = await syncReports(ctx, { source });
      expect(after.staleBuilds).toBeUndefined();
      expect(await row()).toEqual({ pod_digest: null, report_digest: reported, running: reported });
    });

    it("rechecks an image's tags as soon as its running tag changes", async () => {
      db = await freshDb(url);
      const reports = fixtureReports();
      const source = new FakeSource(reports, fixtureOwners());
      const { ctx } = context(db);
      await syncReports(ctx, { source });
      await db.updateTable("images").set({ last_tag_sync_at: "2026-11-12T00:00:00Z" }).execute();

      const api = reportNamed(source.reports as RawReport[], "replicaset-demo-api-7c4967f8db-demo-api");
      api.report.artifact.tag = "next";
      api.report.updateTimestamp = "2030-01-01T00:00:00Z";
      const detail = await syncReports(ctx, { source });
      expect(detail.tagChanges).toBe(1);
      const unsynced = await db.selectFrom("images").select("repository").where("last_tag_sync_at", "is", null).execute();
      expect(unsynced.map((r) => r.repository)).toEqual(["example/demo-api"]);
    });

    it("skips unchanged reports, marks unseen workloads gone, and revives them", async () => {
      db = await freshDb(url);
      const reports = fixtureReports();
      const source = new FakeSource(reports, fixtureOwners());
      const { ctx } = context(db);

      await syncReports(ctx, { source, clock: at("2026-11-08T12:00:00Z") });
      const again = await syncReports(ctx, { source, clock: at("2026-11-08T12:05:00Z") });
      expect(again).toMatchObject({ changedDigests: 0, workloads: 10, markedGone: 0 });

      // demo-api stops being reported. 23h later it is not gone yet; 25h
      // later it is, and nothing else is.
      source.reports = reports.filter((r) => r.metadata.namespace !== "team-a");
      expect((await syncReports(ctx, { source, clock: at("2026-11-09T11:00:00Z") })).markedGone).toBe(0);
      expect((await syncReports(ctx, { source, clock: at("2026-11-09T13:00:00Z") })).markedGone).toBe(1);
      let rows = await workloads(db);
      expect(rows.filter((r) => r.gone_at).map((r) => [r.name, r.gone_at, r.last_seen_at])).toEqual([
        ["demo-api", "2026-11-09T13:00:00.000Z", "2026-11-08T12:05:00.000Z"],
      ]);

      // A later report with a newer digest brings it back.
      const back = structuredClone(reportNamed(reports, "replicaset-demo-api-7c4967f8db-demo-api"));
      back.report.artifact.digest = "sha256:34bee17061a75fc582bbecfe66b70a56f0429ab3917ab2dc9d907eea81a6812c";
      back.report.updateTimestamp = "2026-11-09T14:00:00Z";
      source.reports = [...source.reports, back];
      const revived = await syncReports(ctx, { source, clock: at("2026-11-09T14:05:00Z") });
      expect(revived).toMatchObject({ changedDigests: 1, markedGone: 0 });
      rows = await workloads(db);
      expect(rows.find((r) => r.name === "demo-api")).toMatchObject({
        gone_at: null,
        digest: "sha256:34bee17061a75fc582bbecfe66b70a56f0429ab3917ab2dc9d907eea81a6812c",
      });
    });

    it("does not mark anything gone after an aborted or failed pass", async () => {
      db = await freshDb(url);
      const source = new FakeSource(fixtureReports(), fixtureOwners());
      await syncReports(context(db).ctx, { source, clock: at("2026-11-08T12:00:00Z") });

      const abort = new AbortController();
      abort.abort();
      const aborted = await syncReports(context(db, abort.signal).ctx, { source, clock: at("2026-11-10T12:00:00Z") });
      expect(aborted).toMatchObject({ aborted: true, markedGone: 0 });

      const failing = new FakeSource(fixtureReports(), fixtureOwners());
      let calls = 0;
      failing.listReports = async (p) => {
        if (calls++ > 0) throw Object.assign(new Error("Gone: continue token expired"), { code: 410 });
        return FakeSource.prototype.listReports.call(failing, p);
      };
      await expect(
        syncReports(context(db).ctx, { source: failing, clock: at("2026-11-10T12:00:00Z"), pageSize: 3 }),
      ).rejects.toThrow("continue token expired");
      expect((await workloads(db)).filter((r) => r.gone_at)).toEqual([]);
    });
  });
}
