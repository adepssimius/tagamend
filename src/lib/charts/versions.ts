import { parse as parseYaml } from "yaml";
import type { RegistryClient } from "../registry/client";
import { parseImageRef } from "../registry/hosts";

/**
 * Chart versions: listing them from a repository, and choosing which newer
 * ones to offer. Helm charts use strict semver, unlike image tags, so this
 * does not need tag-shape's heuristics.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
  text: string;
}

const SEMVER = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;

/** Strict semver with an optional leading `v`. Build metadata is accepted and ignored. */
export function parseSemver(text: string): SemVer | null {
  const m = SEMVER.exec(text.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), prerelease: m[4] ?? null, text };
}

/** Semver precedence; positive when `a` is newer. Prerelease identifiers compare per the spec. */
export function compareSemver(a: SemVer, b: SemVer): number {
  const d = a.major - b.major || a.minor - b.minor || a.patch - b.patch;
  if (d !== 0) return d;
  if (a.prerelease === b.prerelease) return 0;
  if (a.prerelease === null) return 1;
  if (b.prerelease === null) return -1;
  const pa = a.prerelease.split(".");
  const pb = b.prerelease.split(".");
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny && Number(x) !== Number(y)) return Number(x) - Number(y);
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Flux records the version of a chart from an OCIRepository with the
 * artifact digest appended as build metadata: `2.4.1+9d4c36d65b6d`. That
 * suffix is not part of the chart's version and helm cannot pull by it.
 */
export function stripFluxDigest(version: string): string {
  return version.replace(/\+[0-9a-f]{12}$/, "");
}

export interface ChartVersion {
  version: string;
  appVersion: string | null;
}

export interface ChartCandidateChoice {
  version: string;
  appVersion: string | null;
  reason: string;
}

export const NEWEST_KEPT = 3;
export const MAJORS_KEPT = 3;

/**
 * Chooses the versions to offer over `installed`: the newest 3 that are newer,
 * the newest of the installed minor line (the smallest step, most likely a
 * drop-in fix), and the newest of each higher major (the 3 highest). Prereleases
 * are never offered.
 */
export function chooseChartCandidates(installed: string, versions: ChartVersion[]): ChartCandidateChoice[] {
  const cur = parseSemver(installed);
  if (!cur) throw new Error(`installed version ${installed} is not semver`);
  const newer: (ChartVersion & { sv: SemVer })[] = [];
  const seen = new Set<string>();
  for (const v of versions) {
    const sv = parseSemver(v.version);
    if (!sv || sv.prerelease !== null || seen.has(v.version)) continue;
    seen.add(v.version);
    if (compareSemver(sv, cur) <= 0) continue;
    newer.push({ ...v, sv });
  }
  newer.sort((a, b) => compareSemver(b.sv, a.sv) || (a.version < b.version ? 1 : -1));

  const reasons = new Map<string, string[]>();
  const add = (v: string, why: string) => reasons.set(v, [...(reasons.get(v) ?? []), why]);

  newer
    .slice(0, NEWEST_KEPT)
    .forEach((v, i) => add(v.version, `${i === 0 ? "newest" : `${ordinal(i + 1)} newest`} chart version after ${installed}`));

  const line = newer.find((v) => v.sv.major === cur.major && v.sv.minor === cur.minor);
  if (line) add(line.version, `newest in ${installed}'s own line (${cur.major}.${cur.minor}.*)`);

  const byMajor = new Map<number, (typeof newer)[number]>();
  for (const v of newer) if (v.sv.major > cur.major && !byMajor.has(v.sv.major)) byMajor.set(v.sv.major, v);
  [...byMajor.entries()]
    .sort((a, b) => b[0] - a[0])
    .slice(0, MAJORS_KEPT)
    .forEach(([m, v]) => add(v.version, `newest in major ${m}, above ${installed}'s major ${cur.major}`));

  return newer
    .filter((v) => reasons.has(v.version))
    .map((v) => ({ version: v.version, appVersion: v.appVersion, reason: reasons.get(v.version)!.join("; ") }));
}

function ordinal(n: number): string {
  return ["", "1st", "2nd", "3rd"][n] ?? `${n}th`;
}

/** Versions of `chart` in a classic repository's index.yaml text. */
export function parseIndex(text: string, chart: string): ChartVersion[] {
  const doc = parseYaml(text, { maxAliasCount: -1 }) as { entries?: Record<string, unknown> } | null;
  const entries = doc?.entries?.[chart];
  if (!Array.isArray(entries)) throw new Error(`chart ${chart} is not in the repository index`);
  const out: ChartVersion[] = [];
  for (const e of entries as { version?: unknown; appVersion?: unknown }[]) {
    if (typeof e?.version !== "string") continue;
    out.push({ version: e.version, appVersion: e.appVersion == null ? null : String(e.appVersion) });
  }
  return out;
}

const INDEX_TIMEOUT_MS = 60_000;
/** Large repositories (prometheus-community) publish an index of tens of MB. */
const INDEX_MAX_BYTES = 128 * 1024 * 1024;

/** GETs `<url>/index.yaml`. */
export async function fetchIndex(url: string, opts: { fetch?: typeof fetch; signal?: AbortSignal } = {}): Promise<string> {
  const indexUrl = `${url.replace(/\/+$/, "")}/index.yaml`;
  const timeout = AbortSignal.timeout(INDEX_TIMEOUT_MS);
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
  const res = await (opts.fetch ?? fetch)(indexUrl, { headers: { "User-Agent": "tagamend" }, signal });
  if (!res.ok) throw new Error(`GET ${indexUrl}: HTTP ${res.status}`);
  const length = Number(res.headers.get("content-length") ?? 0);
  if (length > INDEX_MAX_BYTES) throw new Error(`${indexUrl} is ${length} bytes, over the ${INDEX_MAX_BYTES} limit`);
  return res.text();
}

/** `oci://host/path` to the registry and repository that serve it. */
export function ociLocation(url: string): { registry: string; repository: string } {
  if (!url.startsWith("oci://")) throw new Error(`not an oci:// URL: ${url}`);
  const rest = url.slice("oci://".length).replace(/\/+$/, "");
  const slash = rest.indexOf("/");
  if (slash < 0) throw new Error(`oci URL has no repository: ${url}`);
  const host = rest.slice(0, slash);
  // parseImageRef maps Docker Hub's names to index.docker.io, as `images` stores them.
  const { registry } = parseImageRef(`${host}/x`);
  return { registry, repository: rest.slice(slash + 1) };
}

/**
 * Chart versions in an OCI repository: its semver tags. Helm stores a `+` in
 * a version as `_`, since a tag cannot contain `+`.
 */
export async function listOciVersions(client: RegistryClient, url: string): Promise<ChartVersion[]> {
  const { registry, repository } = ociLocation(url);
  const tags = await client.listTags(registry, repository);
  return tags
    .map((t) => t.replace(/_/g, "+"))
    .filter((t) => parseSemver(t) !== null)
    .map((version) => ({ version, appVersion: null }));
}
