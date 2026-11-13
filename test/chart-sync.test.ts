import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parse, stringify } from "yaml";
import type { K8sObject } from "@/lib/charts/discover";
import type { HelmRunner } from "@/lib/charts/helm";
import { type ChartSource, runChartSync } from "@/lib/charts/sync";
import type { ChartImage, ChartImageChange, PinnedImage } from "@/lib/charts/types";
import { getConfig } from "@/lib/config";
import type { DB } from "@/lib/db";
import { anonymous } from "@/lib/registry/credentials";
import type { Log } from "@/lib/log";
import type { WorkerContext } from "@/lib/worker-context";
import { digestOf, fakeRegistry, type FakeHost } from "./registry-fake";
import { freshDb, testDatabases } from "./helpers";

const HOUR = 3_600_000;
const NOW = Date.parse("2026-11-08T12:00:00.000Z");
const config = getConfig({ DATABASE_URL: ":memory:", TAG_SYNC_INTERVAL: "6h" });
const quiet: Log = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const ctxFor = (db: DB, signal = new AbortController().signal): WorkerContext => ({ db, config, log: quiet, signal });

const INDEX = {
  apiVersion: "v1",
  entries: {
    demo: ["1.0.0", "1.0.1", "1.1.0", "1.5.0", "2.0.0", "2.1.0-rc.1"].map((version) => ({ version, appVersion: `v${version}` })),
  },
};

const registryHosts: Record<string, FakeHost> = {
  "ghcr.io": {
    repos: {
      "example/server": { tags: ["v1.0.0", "v1.0.1", "v1.1.0", "v1.5.0", "v2.0.0"] },
      "example/charts/demo": { tags: ["1.0.0", "1.2.0", "1.2.1_build.1", "2.0.0-rc.1", "latest"] },
    },
  },
  "registry-1.docker.io": { repos: { "library/postgres": { tags: ["16", "17"] } } },
};

/**
 * A fake helm. `pull` writes an empty archive named after the version;
 * `template` renders three workloads from the version and the values file:
 * two that take image tags from values (default v<chart version>) and one
 * that only moves on a major.
 */
function fakeHelm(opts: { failVersions?: string[] } = {}) {
  const calls: string[][] = [];
  const run: HelmRunner = async (args) => {
    calls.push(args);
    if (args[0] === "pull") {
      const version = args[args.indexOf("--version") + 1]!;
      const dest = args[args.indexOf("--destination") + 1]!;
      await writeFile(path.join(dest, `demo-${version}.tgz`), "");
      return { code: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "template") {
      const release = args[1]!;
      const version = /demo-(.+)\.tgz$/.exec(args[2]!)![1]!;
      if (opts.failVersions?.includes(version)) return { code: 1, stdout: "", stderr: "Error: template: demo/templates/x.yaml: boom" };
      const values = (parse(await readFile(args[args.indexOf("--values") + 1]!, "utf8")) ?? {}) as Record<string, any>;
      const tag = (k: string) => values[k]?.image?.tag ?? values.shared?.image?.tag ?? `v${version}`;
      const docs = [
        { kind: "Deployment", metadata: { name: `${release}-server` }, spec: { template: { spec: { containers: [{ name: "s", image: `ghcr.io/example/server:${tag("server")}` }] } } } },
        { kind: "Deployment", metadata: { name: `${release}-worker` }, spec: { template: { spec: { containers: [{ name: "w", image: `ghcr.io/example/server:${tag("worker")}` }] } } } },
        { kind: "StatefulSet", metadata: { name: `${release}-db` }, spec: { template: { spec: { containers: [{ name: "p", image: `postgres:${version.startsWith("1.") ? "16" : "17"}` }] } } } },
      ];
      return { code: 0, stdout: docs.map((d) => `---\n${stringify(d)}`).join(""), stderr: "" };
    }
    return { code: 2, stdout: "", stderr: "unexpected" };
  };
  return { run, calls };
}

function fakeFetch() {
  const reg = fakeRegistry(registryHosts);
  const indexCalls: string[] = [];
  const f = (async (input: URL | RequestInfo, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.host === "charts.example.test") {
      indexCalls.push(url.toString());
      return url.pathname === "/index.yaml" ? new Response(stringify(INDEX)) : new Response("nope", { status: 404 });
    }
    return reg.fetch(input, init);
  }) as typeof fetch;
  return { fetch: f, indexCalls, reg };
}

interface World {
  releases: K8sObject[];
  sources: K8sObject[];
  configMaps: Record<string, Record<string, string>>;
}

function fakeSource(world: World): ChartSource {
  return {
    listHelmReleases: async () => world.releases,
    listSources: async () => world.sources,
    getConfigMap: async (ns, name) => world.configMaps[`${ns}/${name}`] ?? null,
    kubeVersion: async () => "v1.31.0",
  };
}

const demoRelease = (installed: string, extra: Record<string, unknown> = {}): K8sObject => ({
  kind: "HelmRelease",
  metadata: { namespace: "apps", name: "demo", generation: 1 },
  spec: {
    chart: { spec: { chart: "demo", version: installed, sourceRef: { kind: "HelmRepository", name: "example", namespace: "flux" } } },
    values: { server: { image: { tag: "v1.0.0" } }, worker: { image: { tag: "v1.0.0" } }, unused: { image: { tag: "v1.0.0" } } },
    valuesFrom: [
      { kind: "ConfigMap", name: "demo-values" },
      { kind: "Secret", name: "demo-secret" },
    ],
    ...extra,
  },
  status: { history: [{ chartVersion: installed }] },
});

const baseWorld = (): World => ({
  releases: [demoRelease("1.0.0")],
  sources: [
    { kind: "HelmRepository", metadata: { namespace: "flux", name: "example" }, spec: { url: "https://charts.example.test" } },
    { kind: "HelmRepository", metadata: { namespace: "flux", name: "private" }, spec: { url: "https://charts.example.test", secretRef: { name: "x" } } },
    { kind: "OCIRepository", metadata: { namespace: "flux", name: "demo-oci" }, spec: { url: "oci://ghcr.io/example/charts/demo", ref: { tag: "1.0.0" } } },
  ],
  configMaps: { "apps/demo-values": { "values.yaml": "worker:\n  image:\n    tag: v0.9.0\nreplicas: 2\n" } },
});

const chartRows = (db: DB) => db.selectFrom("charts").selectAll().orderBy("name").execute();
const candidateRows = (db: DB, chartId: number) =>
  db.selectFrom("chart_candidates").selectAll().where("chart_id", "=", chartId).orderBy("version").execute();

for (const { name, url } of testDatabases()) {
  describe(`syncCharts (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    const run = (world: World, opts: { helm?: ReturnType<typeof fakeHelm>; net?: ReturnType<typeof fakeFetch>; now?: number; signal?: AbortSignal; fingerprints?: Map<string, string> } = {}) =>
      runChartSync(ctxFor(db, opts.signal), {
        source: fakeSource(world),
        helm: (opts.helm ?? fakeHelm()).run,
        fetch: (opts.net ?? fakeFetch()).fetch,
        credentials: anonymous,
        now: () => opts.now ?? NOW,
        batch: 10,
        fingerprints: opts.fingerprints ?? new Map(),
      });

    it("records candidates, the images they change, and pinned tags", async () => {
      db = await freshDb(url);
      const helm = fakeHelm();
      const out = await run(baseWorld(), { helm });
      expect(out).toMatchObject({ added: 1, synced: 1, errors: 0, candidates: 4, renderErrors: 0 });

      const [chart] = await chartRows(db);
      expect(chart).toMatchObject({
        namespace: "apps",
        name: "demo",
        chart: "demo",
        version: "1.0.0",
        installed_version: "1.0.0",
        source_kind: "HelmRepository",
        source_url: "https://charts.example.test",
        sync_error: null,
        last_sync_at: new Date(NOW).toISOString(),
      });
      expect(chart!.render_note).toMatch(/valuesFrom Secret demo-secret skipped/);
      const current = JSON.parse(chart!.current_images!) as ChartImage[];
      expect(current.map((i) => `${i.key}=${i.ref}`)).toEqual([
        "Deployment/demo-server:spec.template.spec.containers[0].image=ghcr.io/example/server:v1.0.0",
        "Deployment/demo-worker:spec.template.spec.containers[0].image=ghcr.io/example/server:v1.0.0",
        "StatefulSet/demo-db:spec.template.spec.containers[0].image=postgres:16",
      ]);

      const cands = await candidateRows(db, chart!.id);
      expect(cands.map((c) => c.version)).toEqual(["1.0.1", "1.1.0", "1.5.0", "2.0.0"]);
      expect(cands.every((c) => c.is_candidate === 1 && c.render_error === null && c.rendered_at)).toBe(true);
      expect(cands[0]!.reason).toBe("newest in 1.0.0's own line (1.0.*)");
      expect(cands[1]!.reason).toBe("3rd newest chart version after 1.0.0");
      expect(cands[3]!.app_version).toBe("v2.0.0");

      // Pinned images do not move with the chart; the database does on a major.
      expect(JSON.parse(cands[0]!.changes!)).toEqual([]);
      const changes = JSON.parse(cands[3]!.changes!) as ChartImageChange[];
      expect(changes).toHaveLength(1);
      expect(changes[0]).toMatchObject({ key: "StatefulSet/demo-db:spec.template.spec.containers[0].image", from: { tag: "16" }, to: { tag: "17", registry: "index.docker.io", repository: "library/postgres" } });
      expect(changes[0]!.to!.digest).toBe(digestOf(registryHosts["registry-1.docker.io"]!.repos["library/postgres"]!, "17"));

      const pinned = JSON.parse(cands[3]!.pinned!) as PinnedImage[];
      expect(pinned.map((p) => [p.key, p.valuesPath, p.pinnedTag, p.chartDefault?.tag])).toEqual([
        ["Deployment/demo-server:spec.template.spec.containers[0].image", ["server", "image", "tag"], "v1.0.0", "v2.0.0"],
        ["Deployment/demo-worker:spec.template.spec.containers[0].image", ["worker", "image", "tag"], "v1.0.0", "v2.0.0"],
      ]);
      expect(pinned[0]!.chartDefault!.digest).toBe(digestOf(registryHosts["ghcr.io"]!.repos["example/server"]!, "v2.0.0"));

      // Each version is pulled once and rendered as often as needed.
      const pulls = helm.calls.filter((c) => c[0] === "pull");
      expect(pulls.map((c) => c[3]).sort()).toEqual(["1.0.0", "1.0.1", "1.1.0", "1.5.0", "2.0.0"]);
      expect(pulls[0]).toEqual(expect.arrayContaining(["--repo", "https://charts.example.test"]));
      const template = helm.calls.find((c) => c[0] === "template")!;
      expect(template).toEqual(expect.arrayContaining(["--namespace", "apps", "--kube-version", "v1.31.0", "--skip-tests"]));

      const runs = await db.selectFrom("sync_runs").selectAll().where("name", "=", "chart_sync").execute();
      expect(runs).toHaveLength(1);
      expect(runs[0]!.ok).toBe(1);
    });

    it("traces a pin set in a valuesFrom ConfigMap", async () => {
      db = await freshDb(url);
      const world = baseWorld();
      // The worker pin is only in the ConfigMap, and matches the running tag.
      world.configMaps["apps/demo-values"] = { "values.yaml": "worker:\n  image:\n    tag: v1.0.0\n" };
      world.releases[0]!.spec!.values = { server: { image: { tag: "v1.0.0" } } };
      await run(world);
      const [chart] = await chartRows(db);
      const c = (await candidateRows(db, chart!.id)).find((r) => r.version === "2.0.0")!;
      const pinned = JSON.parse(c.pinned!) as PinnedImage[];
      expect(pinned.find((p) => p.name === "demo-worker")!.valuesPath).toEqual(["valuesFrom:ConfigMap/demo-values", "worker", "image", "tag"]);
    });

    it("lists every pin that holds an image when pins are layered", async () => {
      db = await freshDb(url);
      const world = baseWorld();
      world.configMaps = { "apps/demo-values": { "values.yaml": "{}" } };
      // A shared pin all components read, and a specific one that overrides it for the server.
      world.releases[0]!.spec!.values = { shared: { image: { tag: "v1.0.0" } }, server: { image: { tag: "v1.0.0" } } };
      await run(world);
      const [chart] = await chartRows(db);
      const c = (await candidateRows(db, chart!.id)).find((r) => r.version === "2.0.0")!;
      const pinned = JSON.parse(c.pinned!) as PinnedImage[];
      expect(pinned.map((p) => [p.name, p.valuesPath.join("."), p.chartDefault?.tag])).toEqual([
        ["demo-server", "server.image.tag", "v2.0.0"],
        ["demo-server", "shared.image.tag", "v2.0.0"],
        ["demo-worker", "shared.image.tag", "v2.0.0"],
      ]);
    });

    it("is idle until due, and re-checks when the installed version changes", async () => {
      db = await freshDb(url);
      const fingerprints = new Map<string, string>();
      await run(baseWorld(), { fingerprints });
      const idle = await run(baseWorld(), { now: NOW + HOUR, fingerprints });
      expect(idle).toMatchObject({ idle: true, due: 0 });
      expect(await db.selectFrom("sync_runs").selectAll().execute()).toHaveLength(1);

      // A PR was requested for 1.0.1, which the upgrade makes stale.
      const [chart] = await chartRows(db);
      const c101 = (await candidateRows(db, chart!.id)).find((c) => c.version === "1.0.1")!;
      await db
        .insertInto("chart_pull_requests")
        .values({ chart_id: chart!.id, candidate_id: c101.id, to_version: "1.0.1", update_pins: 0, status: "opened", requested_by: "u", requested_at: "2026-11-08T00:00:00Z" })
        .execute();

      const world = baseWorld();
      world.releases = [demoRelease("1.1.0")];
      const out = await run(world, { now: NOW + 2 * HOUR, fingerprints });
      expect(out).toMatchObject({ changed: 1, synced: 1 });
      const cands = await candidateRows(db, chart!.id);
      expect(cands.map((c) => [c.version, c.is_candidate])).toEqual([
        ["1.0.1", 0],
        ["1.5.0", 1],
        ["2.0.0", 1],
      ]);
      expect(cands[0]!.reason).toMatch(/no longer offered/);
      expect(cands.find((c) => c.version === "2.0.0")!.first_seen_at).toBe(new Date(NOW).toISOString());
    });

    it("re-checks when the HelmRelease's spec changes, and is due again after the interval", async () => {
      db = await freshDb(url);
      const fingerprints = new Map<string, string>();
      await run(baseWorld(), { fingerprints });
      const world = baseWorld();
      world.releases[0]!.metadata!.generation = 2;
      expect(await run(world, { now: NOW + HOUR, fingerprints })).toMatchObject({ changed: 1, synced: 1 });
      expect(await run(world, { now: NOW + 8 * HOUR, fingerprints })).toMatchObject({ changed: 0, synced: 1 });
    });

    it("marks a HelmRelease that disappears as gone, and back when it returns", async () => {
      db = await freshDb(url);
      await run(baseWorld());
      const out = await run({ ...baseWorld(), releases: [] }, { now: NOW + HOUR });
      expect(out).toMatchObject({ gone: 1 });
      expect((await chartRows(db))[0]!.gone_at).toBe(new Date(NOW + HOUR).toISOString());
      await run(baseWorld(), { now: NOW + 2 * HOUR });
      expect((await chartRows(db))[0]!.gone_at).toBeNull();
    });

    it("records errors per chart and per candidate and carries on", async () => {
      db = await freshDb(url);
      const world = baseWorld();
      world.releases.push({
        kind: "HelmRelease",
        metadata: { namespace: "apps", name: "private" },
        spec: { chart: { spec: { chart: "demo", version: "1.0.0", sourceRef: { kind: "HelmRepository", name: "private", namespace: "flux" } } } },
        status: { history: [{ chartVersion: "1.0.0" }] },
      });
      world.releases.push({
        kind: "HelmRelease",
        metadata: { namespace: "apps", name: "nocm" },
        spec: {
          chart: { spec: { chart: "demo", version: "1.0.0", sourceRef: { kind: "HelmRepository", name: "example", namespace: "flux" } } },
          valuesFrom: [{ kind: "ConfigMap", name: "missing" }, { kind: "ConfigMap", name: "also-missing", optional: true }],
        },
        status: { history: [{ chartVersion: "1.0.0" }] },
      });
      const net = fakeFetch();
      const out = await run(world, { helm: fakeHelm({ failVersions: ["1.1.0"] }), net });
      expect(out).toMatchObject({ synced: 1, errors: 2, renderErrors: 1 });
      // Two releases share the repository; its index is fetched once.
      expect(net.indexCalls).toHaveLength(1);

      const rows = await chartRows(db);
      expect(rows.find((r) => r.name === "private")!.sync_error).toMatch(/secretRef/);
      expect(rows.find((r) => r.name === "nocm")!.sync_error).toBe("valuesFrom ConfigMap missing does not exist");
      expect(rows.every((r) => r.last_sync_at !== null)).toBe(true);
      const demo = rows.find((r) => r.name === "demo")!;
      const failed = (await candidateRows(db, demo.id)).find((c) => c.version === "1.1.0")!;
      expect(failed.render_error).toMatch(/helm template demo-1\.1\.0\.tgz: Error: template: .*boom/);
      expect(failed.changes).toBeNull();
    });

    it("lists an OCIRepository chart's versions from its tags", async () => {
      db = await freshDb(url);
      const world = baseWorld();
      world.releases = [
        {
          kind: "HelmRelease",
          metadata: { namespace: "apps", name: "demo" },
          spec: { chartRef: { kind: "OCIRepository", name: "demo-oci", namespace: "flux" } },
          status: { history: [{ chartVersion: "1.0.0+0123456789ab" }] },
        },
      ];
      const helm = fakeHelm();
      await run(world, { helm });
      const [chart] = await chartRows(db);
      expect(chart).toMatchObject({ source_kind: "OCIRepository", source_url: "oci://ghcr.io/example/charts/demo", installed_version: "1.0.0", version: "1.0.0" });
      expect((await candidateRows(db, chart!.id)).map((c) => c.version)).toEqual(["1.2.0", "1.2.1+build.1"]);
      const pull = helm.calls.find((c) => c[0] === "pull")!;
      expect(pull[1]).toBe("oci://ghcr.io/example/charts/demo");
      expect(pull).not.toContain("--repo");
    });

    it("does nothing once stopping", async () => {
      db = await freshDb(url);
      const ac = new AbortController();
      ac.abort();
      const helm = fakeHelm();
      const out = await run(baseWorld(), { helm, signal: ac.signal });
      expect(out).toMatchObject({ skipped: "stopping" });
      expect(helm.calls).toHaveLength(0);
    });
  });
}
