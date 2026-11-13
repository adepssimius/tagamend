import { parse as parseYaml } from "yaml";
import type { DB } from "../db";
import type { Chart } from "../db/schema";
import { withSyncRun } from "../db/store";
import { errorMessage } from "../log";
import { RegistryClient } from "../registry/client";
import { type CredentialLookup, fileCredentials } from "../registry/credentials";
import type { WorkerContext } from "../worker-context";
import { type ChartRelease, describeRelease, indexSources, type K8sObject } from "./discover";
import { HelmWorkspace, type HelmRunner, spawnHelm } from "./helm";
import { diffImages, extractImages } from "./images";
import type { ChartImage, ChartImageChange, PinnedImage } from "./types";
import { findTagKeys, isMap, mergeLayers, type Values, type ValuesLayer, valuesAtTargetPath, withoutKey } from "./values";
import { type ChartVersion, chooseChartCandidates, fetchIndex, listOciVersions, parseIndex, parseSemver } from "./versions";

/** Where chart sync reads the cluster. Injectable so tests need no cluster. Read-only. */
export interface ChartSource {
  /** Every Flux HelmRelease, all namespaces. */
  listHelmReleases(): Promise<K8sObject[]>;
  /** Every HelmRepository and OCIRepository, all namespaces, with `kind` set. */
  listSources(): Promise<K8sObject[]>;
  /** A ConfigMap's data, or null when it does not exist. */
  getConfigMap(namespace: string, name: string): Promise<Record<string, string> | null>;
  /** The API server's version, for helm's Capabilities.KubeVersion. */
  kubeVersion?(): Promise<string | null>;
}

export interface ChartSyncOptions {
  source?: ChartSource;
  helm?: HelmRunner;
  /** For repository indexes and the registry. */
  fetch?: typeof fetch;
  credentials?: CredentialLookup;
  now?: () => number;
  /** Charts per tick; computed from the interval when not given. */
  batch?: number;
  /** HelmRelease fingerprints seen so far, by "namespace/name". */
  fingerprints?: Map<string, string>;
}

/** At least this many charts per tick, so a first pass does not take the whole interval. */
const MIN_CHARTS_PER_TICK = 2;
const TICK_MS = 60_000;
/** Pins traced per candidate; each costs one more render. */
const MAX_PINS = 10;

/** Kept between ticks: the worker is one process. A restart only loses the "values changed" trigger. */
const seenFingerprints = new Map<string, string>();
let kubeVersion: string | null | undefined;

/**
 * Chart upgrades. Called every minute. Finds Flux HelmReleases, lists newer
 * chart versions, renders each with the HelmRelease's values, and records the
 * images each candidate changes.
 */
export async function syncCharts(ctx: WorkerContext): Promise<Record<string, unknown>> {
  return runChartSync(ctx);
}

export async function runChartSync(ctx: WorkerContext, opts: ChartSyncOptions = {}): Promise<Record<string, unknown>> {
  const nowMs = opts.now ?? Date.now;
  const source = opts.source ?? (await import("./source")).k8sChartSource();
  const fingerprints = opts.fingerprints ?? seenFingerprints;

  const [releases, sourceObjects] = await Promise.all([source.listHelmReleases(), source.listSources()]);
  const sources = indexSources(sourceObjects);
  const described = new Map<string, ChartRelease>();
  let unsupportedKinds = 0;
  for (const hr of releases) {
    const r = describeRelease(hr, sources);
    if (r) described.set(`${r.namespace}/${r.name}`, r);
    else unsupportedKinds++;
  }

  const at = new Date(nowMs()).toISOString();
  const discovery = await upsertCharts(ctx.db, described, fingerprints, at);

  const cutoff = new Date(nowMs() - ctx.config.TAG_SYNC_INTERVAL).toISOString();
  const live = await ctx.db.selectFrom("charts").selectAll().where("gone_at", "is", null).execute();
  const due = live
    .filter((c) => c.last_sync_at === null || c.last_sync_at < cutoff)
    .sort((a, b) => (a.last_sync_at ?? "").localeCompare(b.last_sync_at ?? "") || a.id - b.id);
  const batch = opts.batch ?? Math.max(MIN_CHARTS_PER_TICK, Math.ceil((live.length * TICK_MS) / ctx.config.TAG_SYNC_INTERVAL));
  const todo = due.slice(0, batch);

  const summary = { charts: live.length, ...discovery, unsupportedKinds, due: due.length };
  if (todo.length === 0 && discovery.added === 0 && discovery.gone === 0) return { idle: true, ...summary };
  if (ctx.signal.aborted) return { skipped: "stopping" };

  return (
    (await withSyncRun(ctx.db, "chart_sync", async () => {
      const counts = { ...summary, synced: 0, errors: 0, candidates: 0, renders: 0, renderErrors: 0 };
      if (todo.length === 0) return counts;

      // Read once per process from the cluster; an injected source is asked each time.
      const readKubeVersion = async () => (await source.kubeVersion?.().catch(() => null)) ?? null;
      const kv = opts.source ? await readKubeVersion() : (kubeVersion ??= await readKubeVersion());
      const deps: Deps = {
        db: ctx.db,
        source,
        signal: ctx.signal,
        fetch: opts.fetch,
        workspace: new HelmWorkspace(opts.helm ?? spawnHelm(ctx.config.HELM_BIN), { signal: ctx.signal, kubeVersion: kv }),
        registry: new RegistryClient({
          fetch: opts.fetch,
          credentials: opts.credentials ?? fileCredentials(ctx.config.REGISTRY_CREDENTIALS_DIR),
          signal: ctx.signal,
          now: nowMs,
        }),
        indexes: new Map(),
        digests: new Map(),
        now: () => new Date(nowMs()).toISOString(),
      };
      try {
        for (const chart of todo) {
          if (ctx.signal.aborted) break;
          const release = described.get(`${chart.namespace}/${chart.name}`);
          if (!release) continue;
          try {
            const out = await syncChart(deps, chart, release);
            counts.synced++;
            counts.candidates += out.candidates;
            counts.renders += out.renders;
            counts.renderErrors += out.renderErrors;
          } catch (e) {
            if (ctx.signal.aborted) break;
            // A broken chart waits for the next interval rather than retrying every minute.
            counts.errors++;
            const message = errorMessage(e);
            await ctx.db
              .updateTable("charts")
              .set({ sync_error: message, last_sync_at: deps.now() })
              .where("id", "=", chart.id)
              .execute();
            ctx.log.warn("chart sync failed", { namespace: chart.namespace, name: chart.name, error: message });
          }
        }
      } finally {
        await deps.workspace.close();
      }
      return counts;
    })) ?? {}
  );
}

/**
 * Records every HelmRelease in `charts`. A release whose chart, version,
 * installed version, source or values changed is made due now; one that is no
 * longer listed is marked gone.
 */
async function upsertCharts(
  db: DB,
  described: Map<string, ChartRelease>,
  fingerprints: Map<string, string>,
  at: string,
): Promise<{ added: number; changed: number; gone: number }> {
  const rows = await db.selectFrom("charts").selectAll().execute();
  const byKey = new Map(rows.map((r) => [`${r.namespace}/${r.name}`, r]));
  const out = { added: 0, changed: 0, gone: 0 };

  for (const [key, r] of described) {
    const values = {
      chart: r.chart,
      version: r.version,
      installed_version: r.installedVersion,
      source_kind: r.sourceKind,
      source_url: r.sourceUrl,
    };
    const row = byKey.get(key);
    const seen = fingerprints.get(key);
    fingerprints.set(key, r.fingerprint);
    if (!row) {
      await db
        .insertInto("charts")
        .values({ namespace: r.namespace, name: r.name, ...values, last_sync_at: null, gone_at: null })
        .onConflict((oc) => oc.columns(["namespace", "name"]).doNothing())
        .execute();
      out.added++;
      continue;
    }
    const changed =
      row.chart !== values.chart ||
      row.version !== values.version ||
      row.installed_version !== values.installed_version ||
      row.source_kind !== values.source_kind ||
      row.source_url !== values.source_url ||
      row.gone_at !== null ||
      (seen !== undefined && seen !== r.fingerprint);
    if (!changed) continue;
    out.changed++;
    await db
      .updateTable("charts")
      .set({ ...values, gone_at: null, last_sync_at: null })
      .where("id", "=", row.id)
      .execute();
  }

  const gone = rows.filter((r) => r.gone_at === null && !described.has(`${r.namespace}/${r.name}`));
  for (const r of gone) fingerprints.delete(`${r.namespace}/${r.name}`);
  if (gone.length) {
    await db.updateTable("charts").set({ gone_at: at }).where("id", "in", gone.map((r) => r.id)).execute();
    out.gone = gone.length;
  }
  return out;
}

interface Deps {
  db: DB;
  source: ChartSource;
  signal: AbortSignal;
  fetch?: typeof fetch;
  workspace: HelmWorkspace;
  registry: RegistryClient;
  /** Repository index text by URL, for this tick: several releases can share a repository. */
  indexes: Map<string, Promise<string>>;
  /** Image digests by reference, for this tick. */
  digests: Map<string, Promise<string | null>>;
  now: () => string;
}

interface CandidateRow {
  version: string;
  app_version: string | null;
  is_candidate: number;
  reason: string;
  rendered_at: string | null;
  render_error: string | null;
  changes: string | null;
  pinned: string | null;
}

async function syncChart(
  deps: Deps,
  chart: Chart,
  release: ChartRelease,
): Promise<{ candidates: number; renders: number; renderErrors: number }> {
  if (release.unsupported) throw new Error(release.unsupported);
  const installed = release.installedVersion ?? (parseSemver(release.version) ? release.version : null);
  if (!installed) throw new Error(`installed version is not known and spec version ${release.version} is not exact`);
  if (!parseSemver(installed)) throw new Error(`installed version ${installed} is not semver`);

  const versions = await listVersions(deps, release);
  const choices = chooseChartCandidates(installed, versions);
  const { layers, notes } = await loadValues(deps.source, release);
  const merged = mergeLayers(layers);
  const loc = { pullRef: release.pullRef, repo: release.repo };
  const target = { name: release.releaseName, namespace: release.releaseNamespace };
  let renders = 0;
  let renderErrors = 0;

  const render = async (version: string, values: Values): Promise<ChartImage[]> => {
    renders++;
    const archive = await deps.workspace.pull(loc, version);
    return extractImages(await deps.workspace.template(archive, target, values));
  };

  let current: ChartImage[] | null = null;
  let currentError: string | null = null;
  try {
    current = await render(installed, merged);
  } catch (e) {
    if (deps.signal.aborted) throw e;
    renderErrors++;
    currentError = `installed version ${installed} did not render: ${errorMessage(e)}`;
  }

  const rows: CandidateRow[] = [];
  for (const c of choices) {
    if (deps.signal.aborted) throw new Error("stopping");
    const row: CandidateRow = {
      version: c.version,
      app_version: c.appVersion,
      is_candidate: 1,
      reason: c.reason,
      rendered_at: null,
      render_error: null,
      changes: null,
      pinned: null,
    };
    rows.push(row);
    if (!current) {
      row.render_error = currentError;
      continue;
    }
    try {
      const images = await render(c.version, merged);
      const changes: ChartImageChange[] = diffImages(current, images);
      for (const ch of changes) if (ch.to) ch.to = await withDigest(deps, ch.to);
      const pinned = await tracePins(deps, layers, merged, images, (values) => render(c.version, values));
      row.changes = JSON.stringify(changes);
      row.pinned = JSON.stringify(pinned);
      row.rendered_at = deps.now();
    } catch (e) {
      if (deps.signal.aborted) throw e;
      renderErrors++;
      row.render_error = errorMessage(e);
    }
  }

  await deps.db.transaction().execute(async (trx) => {
    const at = deps.now();
    for (const row of rows) {
      const { version, ...values } = row;
      await trx
        .insertInto("chart_candidates")
        .values({ chart_id: chart.id, version, first_seen_at: at, ...values })
        .onConflict((oc) => oc.columns(["chart_id", "version"]).doUpdateSet(values))
        .execute();
    }
    // A candidate a PR was requested for stays, so deleting it does not take
    // the PR's record with it (the foreign key cascades).
    const stale = await trx
      .selectFrom("chart_candidates")
      .select(["id", "version"])
      .where("chart_id", "=", chart.id)
      .where("version", "not in", rows.length ? rows.map((r) => r.version) : [""])
      .execute();
    if (stale.length) {
      const withPr = new Set(
        (
          await trx
            .selectFrom("chart_pull_requests")
            .select("candidate_id")
            .where("candidate_id", "in", stale.map((s) => s.id))
            .execute()
        ).map((p) => p.candidate_id),
      );
      const drop = stale.filter((s) => !withPr.has(s.id)).map((s) => s.id);
      const keep = stale.filter((s) => withPr.has(s.id)).map((s) => s.id);
      if (drop.length) await trx.deleteFrom("chart_candidates").where("id", "in", drop).execute();
      if (keep.length) {
        await trx
          .updateTable("chart_candidates")
          .set({ is_candidate: 0, reason: `no longer offered over installed ${installed}` })
          .where("id", "in", keep)
          .execute();
      }
    }
    await trx
      .updateTable("charts")
      .set({
        last_sync_at: at,
        sync_error: currentError,
        current_images: current ? JSON.stringify(current) : null,
        render_note: notes.length ? notes.join("; ") : null,
      })
      .where("id", "=", chart.id)
      .execute();
  });

  return { candidates: rows.length, renders, renderErrors };
}

async function listVersions(deps: Deps, release: ChartRelease): Promise<ChartVersion[]> {
  if (release.ociUrl) return listOciVersions(deps.registry, release.ociUrl);
  const url = release.repo!;
  let text = deps.indexes.get(url);
  if (!text) {
    text = fetchIndex(url, { fetch: deps.fetch, signal: deps.signal });
    text.catch(() => deps.indexes.delete(url));
    deps.indexes.set(url, text);
  }
  return parseIndex(await text, release.chart);
}

/**
 * The HelmRelease's values as layers in Flux's order: each valuesFrom source,
 * then spec.values. Secrets are never read: a value from one is missing from
 * the render, and the note says so.
 */
export async function loadValues(
  source: ChartSource,
  release: ChartRelease,
): Promise<{ layers: ValuesLayer[]; notes: string[] }> {
  const layers: ValuesLayer[] = [];
  const notes: string[] = [];
  for (const ref of release.valuesFrom) {
    const what = `valuesFrom ${ref.kind} ${ref.name}`;
    if (ref.kind === "Secret") {
      notes.push(`${what} skipped: Secrets are not read, so values from it are missing from the renders`);
      continue;
    }
    if (ref.kind !== "ConfigMap") {
      notes.push(`${what} skipped: unknown kind`);
      continue;
    }
    const data = await source.getConfigMap(release.namespace, ref.name);
    const key = ref.valuesKey ?? "values.yaml";
    const text = data?.[key];
    if (text === undefined) {
      const why = data ? `has no key ${key}` : "does not exist";
      if (ref.optional) {
        notes.push(`${what} ${why} (optional)`);
        continue;
      }
      throw new Error(`${what} ${why}`);
    }
    if (ref.targetPath) {
      const values = valuesAtTargetPath(ref.targetPath, text);
      if (!values) {
        notes.push(`${what} skipped: targetPath ${ref.targetPath} is not a plain dotted path`);
        continue;
      }
      layers.push({ origin: `ConfigMap/${ref.name}`, values });
      continue;
    }
    const parsed = parseYaml(text, { maxAliasCount: -1 }) as unknown;
    if (parsed == null) continue;
    if (!isMap(parsed)) throw new Error(`${what} key ${key} is not a YAML map`);
    layers.push({ origin: `ConfigMap/${ref.name}`, values: parsed });
  }
  layers.push({ origin: "inline", values: release.values });
  if (release.postRenderers) notes.push("postRenderers are not applied, so images they patch are not shown");
  return { layers, notes };
}

/**
 * Images the values pin with a `tag:` key, and what the chart would run
 * without the pins.
 *
 * The candidate is rendered once with every pin removed (pins whose value is
 * the tag of an image it renders); an image that changes is pinned, and what
 * it changes to is the chart's default. Then, for each pin, it is rendered
 * with only that pin kept: the images that pin alone holds at the pinned tag
 * are attributed to it. Charts often layer pins (immich reads a shared
 * `controllers.main...image.tag` and a per-component one), so an image can be
 * held by several pins, and each pair is listed: to move the image, a PR moves
 * every pin listed for it. A pin that holds nothing (unused, or equal to the
 * chart default) is left out.
 *
 * valuesPath is relative to spec.values when the pin is written there. A pin
 * from a valuesFrom ConfigMap has the marker "valuesFrom:ConfigMap/<name>" as
 * its first element, followed by the path inside that ConfigMap's values.
 */
async function tracePins(
  deps: Deps,
  layers: ValuesLayer[],
  merged: Values,
  images: ChartImage[],
  render: (values: Values) => Promise<ChartImage[]>,
): Promise<PinnedImage[]> {
  const tags = new Set(images.map((i) => i.tag).filter((t): t is string => t !== null));
  const pins = findTagKeys(layers)
    .filter((k) => tags.has(k.value))
    .slice(0, MAX_PINS);
  if (pins.length === 0) return [];
  const without = (keep: number | null) => pins.reduce((v, p, i) => (i === keep ? v : withoutKey(v, p.path)), merged);

  const pinnedRender = new Map(images.map((i) => [i.key, i]));
  const defaults = new Map<string, ChartImage>();
  for (const img of await render(without(null))) {
    const before = pinnedRender.get(img.key);
    if (before && before.ref !== img.ref && before.tag !== null && pins.some((p) => p.value === before.tag)) defaults.set(img.key, img);
  }
  if (defaults.size === 0) return [];

  const out: PinnedImage[] = [];
  for (const [i, pin] of pins.entries()) {
    if (deps.signal.aborted) throw new Error("stopping");
    const onlyThis = new Map((await render(without(i))).map((img) => [img.key, img]));
    for (const [key, chartDefault] of defaults) {
      const before = pinnedRender.get(key)!;
      if (before.tag !== pin.value || onlyThis.get(key)?.ref !== before.ref) continue;
      out.push({
        key,
        kind: before.kind,
        name: before.name,
        valuesPath: pin.origin === "inline" ? pin.path : [`valuesFrom:${pin.origin}`, ...pin.path],
        pinnedTag: pin.value,
        chartDefault: await withDigest(deps, chartDefault),
      });
    }
  }
  return out.sort((a, b) => a.key.localeCompare(b.key) || a.valuesPath.join(".").localeCompare(b.valuesPath.join(".")));
}

/** The image with its digest from the registry; null digest when it cannot be resolved. */
async function withDigest(deps: Deps, img: ChartImage): Promise<ChartImage> {
  if (img.digest || !img.tag) return img;
  const ref = `${img.registry}/${img.repository}:${img.tag}`;
  let p = deps.digests.get(ref);
  if (!p) {
    p = deps.registry.headManifest(img.registry, img.repository, img.tag).catch(() => null);
    deps.digests.set(ref, p);
  }
  return { ...img, digest: await p };
}
