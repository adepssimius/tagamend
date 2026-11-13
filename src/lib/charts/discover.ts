import { stripFluxDigest } from "./versions";

/**
 * Reads Flux HelmReleases and their sources into the facts chart sync needs.
 * Pure: the objects come from a ChartSource.
 */

export interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: { namespace?: string; name?: string; generation?: number };
  spec?: Record<string, unknown>;
  status?: Record<string, unknown>;
}

export interface ValuesReference {
  kind: string;
  name: string;
  valuesKey?: string;
  targetPath?: string;
  optional?: boolean;
}

export interface ChartRelease {
  /** The HelmRelease. */
  namespace: string;
  name: string;
  /** What helm calls the release, and the namespace it installs into. */
  releaseName: string;
  releaseNamespace: string;
  chart: string;
  /** spec.chart.spec.version, or the OCIRepository's ref, as written. */
  version: string;
  installedVersion: string | null;
  sourceKind: "HelmRepository" | "OCIRepository";
  /** https://..., or oci://... (a repository for HelmRepository, the chart itself for OCIRepository). */
  sourceUrl: string;
  /** What `helm pull` takes: a chart name with `repo`, or a full oci:// reference. */
  pullRef: string;
  repo: string | null;
  /** The OCI repository whose tags are the chart's versions; null for a classic repository. */
  ociUrl: string | null;
  values: Record<string, unknown>;
  valuesFrom: ValuesReference[];
  postRenderers: boolean;
  /** Changes when the HelmRelease's spec or what Flux last applied changes. */
  fingerprint: string;
  /** Set when the chart cannot be checked, with the reason. */
  unsupported: string | null;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);
const obj = (v: unknown): Record<string, unknown> =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};

const sourceKey = (kind: string, namespace: string, name: string) => `${kind}/${namespace}/${name}`;

/** Indexes HelmRepository and OCIRepository objects for `describeRelease`. */
export function indexSources(objects: K8sObject[]): Map<string, K8sObject> {
  const out = new Map<string, K8sObject>();
  for (const o of objects) {
    if (!o.kind || !o.metadata?.namespace || !o.metadata.name) continue;
    out.set(sourceKey(o.kind, o.metadata.namespace, o.metadata.name), o);
  }
  return out;
}

/** A source's settings this worker cannot honour yet, or null. */
function unsupportedSource(source: K8sObject): string | null {
  const spec = obj(source.spec);
  const what = `${source.kind} ${source.metadata?.namespace}/${source.metadata?.name}`;
  if (str(obj(spec.secretRef).name)) return `${what} uses credentials (secretRef), which chart sync does not support yet`;
  if (str(obj(spec.certSecretRef).name)) return `${what} uses a client certificate (certSecretRef), which chart sync does not support yet`;
  const provider = str(spec.provider);
  if (provider && provider !== "generic") return `${what} uses provider ${provider}, which chart sync does not support yet`;
  return null;
}

/**
 * The chart a HelmRelease installs and where it comes from. Returns null for
 * a release whose chart is not from a Helm or OCI repository (GitRepository,
 * Bucket, HelmChart), which has no versions to list.
 */
export function describeRelease(hr: K8sObject, sources: Map<string, K8sObject>): ChartRelease | null {
  const namespace = hr.metadata?.namespace ?? "";
  const name = hr.metadata?.name ?? "";
  const spec = obj(hr.spec);
  const status = obj(hr.status);
  const targetNamespace = str(spec.targetNamespace);
  const releaseName = str(spec.releaseName) ?? (targetNamespace ? `${targetNamespace}-${name}` : name);
  const history = Array.isArray(status.history) ? (status.history as unknown[]) : [];
  const rawInstalled = str(obj(history[0]).chartVersion) ?? str(status.lastAttemptedRevision) ?? null;

  const valuesFrom: ValuesReference[] = [];
  for (const v of Array.isArray(spec.valuesFrom) ? (spec.valuesFrom as unknown[]) : []) {
    const r = obj(v);
    const kind = str(r.kind);
    const refName = str(r.name);
    if (!kind || !refName) continue;
    valuesFrom.push({
      kind,
      name: refName,
      valuesKey: str(r.valuesKey),
      targetPath: str(r.targetPath),
      optional: r.optional === true,
    });
  }
  const postRenderers = Array.isArray(spec.postRenderers) && spec.postRenderers.length > 0;
  const fingerprint = JSON.stringify([
    hr.metadata?.generation ?? null,
    rawInstalled,
    str(status.lastAttemptedConfigDigest) ?? str(status.lastAttemptedValuesChecksum) ?? null,
  ]);
  const base = {
    namespace,
    name,
    releaseName,
    releaseNamespace: targetNamespace ?? namespace,
    values: obj(spec.values),
    valuesFrom,
    postRenderers,
    fingerprint,
  };

  const chartRef = obj(spec.chartRef);
  if (str(chartRef.kind)) {
    if (chartRef.kind !== "OCIRepository") return null;
    const srcNs = str(chartRef.namespace) ?? namespace;
    const srcName = str(chartRef.name) ?? "";
    const source = sources.get(sourceKey("OCIRepository", srcNs, srcName));
    const url = str(obj(source?.spec).url) ?? "";
    const ref = obj(obj(source?.spec).ref);
    return {
      ...base,
      chart: url.replace(/\/+$/, "").split("/").pop() ?? "",
      version: str(ref.tag) ?? str(ref.semver) ?? str(ref.digest) ?? "latest",
      installedVersion: rawInstalled ? stripFluxDigest(rawInstalled) : null,
      sourceKind: "OCIRepository",
      sourceUrl: url,
      pullRef: url,
      repo: null,
      ociUrl: url,
      unsupported: !source
        ? `OCIRepository ${srcNs}/${srcName} not found`
        : !url.startsWith("oci://")
          ? `OCIRepository ${srcNs}/${srcName} has no oci:// URL`
          : unsupportedSource(source),
    };
  }

  const chartSpec = obj(obj(spec.chart).spec);
  const sourceRef = obj(chartSpec.sourceRef);
  if (sourceRef.kind !== "HelmRepository") return null;
  const chart = str(chartSpec.chart) ?? "";
  const srcNs = str(sourceRef.namespace) ?? namespace;
  const srcName = str(sourceRef.name) ?? "";
  const source = sources.get(sourceKey("HelmRepository", srcNs, srcName));
  const url = (str(obj(source?.spec).url) ?? "").replace(/\/+$/, "");
  const oci = obj(source?.spec).type === "oci" || url.startsWith("oci://");
  return {
    ...base,
    chart,
    version: str(chartSpec.version) ?? "*",
    installedVersion: rawInstalled,
    sourceKind: "HelmRepository",
    sourceUrl: url,
    pullRef: oci ? `${url}/${chart}` : chart,
    repo: oci ? null : url,
    ociUrl: oci ? `${url}/${chart}` : null,
    unsupported: !source
      ? `HelmRepository ${srcNs}/${srcName} not found`
      : !url
        ? `HelmRepository ${srcNs}/${srcName} has no URL`
        : unsupportedSource(source),
  };
}
