import { execFileSync } from "node:child_process";
import { readFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawnHelm } from "@/lib/charts/helm";
import { type ChartSource, runChartSync } from "@/lib/charts/sync";
import type { ChartImage, ChartImageChange, PinnedImage } from "@/lib/charts/types";
import { getConfig } from "@/lib/config";
import { freshDb } from "./helpers";
import { fakeRegistry } from "./registry-fake";

/**
 * Renders a real chart with the real helm binary, from a chart repository
 * served on localhost. Skipped when helm is not installed.
 */
const HELM = process.env.HELM_BIN ?? "helm";
const haveHelm = (() => {
  try {
    execFileSync(HELM, ["version", "--short"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

const chartYaml = (version: string) => `apiVersion: v2
name: demo
version: ${version}
appVersion: v${version}
`;
const deployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
  namespace: {{ .Release.Namespace }}
spec:
  replicas: {{ .Values.replicas }}
  template:
    spec:
      containers:
        - name: app
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
        - name: sidecar
          image: {{ .Values.sidecar.image }}
`;
const defaults = (sidecar: string) => `replicas: 1
image:
  repository: ghcr.io/example/app
  tag: ""
sidecar:
  image: ${sidecar}
`;

describe.skipIf(!haveHelm)("chart sync with real helm", () => {
  let dir: string;
  let server: Server;
  let repoUrl: string;
  const saved = { cache: process.env.HELM_CACHE_HOME, config: process.env.HELM_CONFIG_HOME, data: process.env.HELM_DATA_HOME };

  beforeAll(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "tagamend-helm-test-"));
    process.env.HELM_CACHE_HOME = path.join(dir, "home/cache");
    process.env.HELM_CONFIG_HOME = path.join(dir, "home/config");
    process.env.HELM_DATA_HOME = path.join(dir, "home/data");
    const repo = path.join(dir, "repo");
    await mkdir(repo);
    for (const [version, sidecar] of [["1.0.0", "busybox:1.36"], ["1.1.0", "busybox:1.37"]] as const) {
      const src = path.join(dir, `src-${version}`, "demo");
      await mkdir(path.join(src, "templates"), { recursive: true });
      await writeFile(path.join(src, "Chart.yaml"), chartYaml(version));
      await writeFile(path.join(src, "values.yaml"), defaults(sidecar));
      await writeFile(path.join(src, "templates", "deployment.yaml"), deployment);
      execFileSync(HELM, ["package", src, "--destination", repo], { stdio: "ignore" });
    }
    server = createServer(async (req, res) => {
      try {
        res.end(await readFile(path.join(repo, path.basename(req.url ?? ""))));
      } catch {
        res.statusCode = 404;
        res.end();
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    repoUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    execFileSync(HELM, ["repo", "index", repo, "--url", repoUrl], { stdio: "ignore" });
  });

  afterAll(async () => {
    server?.close();
    if (dir) await rm(dir, { recursive: true, force: true });
    for (const [k, v] of [["HELM_CACHE_HOME", saved.cache], ["HELM_CONFIG_HOME", saved.config], ["HELM_DATA_HOME", saved.data]] as const) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it("renders the installed and candidate versions and traces the pinned tag", async () => {
    const db = await freshDb(":memory:");
    try {
      const reg = fakeRegistry({
        "ghcr.io": { repos: { "example/app": { tags: ["v1.0.0", "v1.1.0"] } } },
        "registry-1.docker.io": { repos: { "library/busybox": { tags: ["1.36", "1.37"] } } },
      });
      const net = (async (input: URL | RequestInfo, init?: RequestInit) =>
        String(input).startsWith(repoUrl) ? fetch(input, init) : reg.fetch(input, init)) as typeof fetch;
      const source: ChartSource = {
        listHelmReleases: async () => [
          {
            kind: "HelmRelease",
            metadata: { namespace: "apps", name: "demo" },
            spec: {
              targetNamespace: "web",
              chart: { spec: { chart: "demo", version: "1.0.0", sourceRef: { kind: "HelmRepository", name: "local" } } },
              values: { replicas: 2, image: { tag: "v1.0.0" } },
            },
            status: { history: [{ chartVersion: "1.0.0" }] },
          },
        ],
        listSources: async () => [{ kind: "HelmRepository", metadata: { namespace: "apps", name: "local" }, spec: { url: repoUrl } }],
        getConfigMap: async () => null,
      };
      const config = getConfig({ DATABASE_URL: ":memory:", HELM_BIN: HELM });
      const out = await runChartSync(
        { db, config, log: { debug() {}, info() {}, warn() {}, error() {} }, signal: new AbortController().signal },
        { source, helm: spawnHelm(HELM), fetch: net, fingerprints: new Map(), batch: 5 },
      );
      expect(out).toMatchObject({ synced: 1, errors: 0, renderErrors: 0, candidates: 1 });

      const chart = await db.selectFrom("charts").selectAll().executeTakeFirstOrThrow();
      expect(chart.sync_error).toBeNull();
      const current = JSON.parse(chart.current_images!) as ChartImage[];
      expect(current.map((i) => `${i.key}=${i.ref}`)).toEqual([
        "Deployment/web-demo-app:spec.template.spec.containers[0].image=ghcr.io/example/app:v1.0.0",
        "Deployment/web-demo-app:spec.template.spec.containers[1].image=busybox:1.36",
      ]);

      const cand = await db.selectFrom("chart_candidates").selectAll().executeTakeFirstOrThrow();
      expect(cand).toMatchObject({ version: "1.1.0", app_version: "v1.1.0", render_error: null });
      const changes = JSON.parse(cand.changes!) as ChartImageChange[];
      expect(changes.map((c) => [c.key, c.from?.ref, c.to?.ref])).toEqual([
        ["Deployment/web-demo-app:spec.template.spec.containers[1].image", "busybox:1.36", "busybox:1.37"],
      ]);
      expect(changes[0]!.to!.digest).toMatch(/^sha256:/);
      const pinned = JSON.parse(cand.pinned!) as PinnedImage[];
      expect(pinned).toHaveLength(1);
      expect(pinned[0]).toMatchObject({ valuesPath: ["image", "tag"], pinnedTag: "v1.0.0", chartDefault: { ref: "ghcr.io/example/app:v1.1.0" } });
    } finally {
      await db.destroy();
    }
  }, 60_000);
});
