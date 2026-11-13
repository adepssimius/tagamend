import type { PinnedImage } from "../charts/types";
import { applySpans, type ChartEdit, ChartEditError, findDoc, findDocs, type FoundDoc, isExactVersion, planScalar, type Span } from "./chart-yaml";

/** Where the chart version is written and what it said. */
export interface VersionSite {
  kind: "HelmRelease" | "OCIRepository";
  namespace: string;
  name: string;
  path: string;
  /** Dotted key path, e.g. "spec.chart.spec.version" or "spec.ref.tag". */
  field: string;
  /** The value as written before this PR. */
  was: string;
  /** `was` was a range (`*`, `>=1.0`, `~1.2`) rather than one version. */
  wasRange: boolean;
  /** Other HelmReleases that use the same OCIRepository, and so move too. */
  sharedWith: string[];
}

export interface PinOutcome {
  pin: PinnedImage;
  /** "moved": this PR sets it to the chart default; "kept": pins were not asked to move; "same": already the default. */
  outcome: "moved" | "kept" | "same";
}

export interface ChartPlan {
  /** Only the files that changed, with their new contents. */
  files: Map<string, string>;
  edits: ChartEdit[];
  version: VersionSite;
  pins: PinOutcome[];
}

const objectId = (d: FoundDoc) => `${d.kind}/${d.namespace ?? "?"}/${d.name}`;

/**
 * Plans the edits that move a HelmRelease to `toVersion`: the chart version
 * (on the HelmRelease, or on the OCIRepository its spec.chartRef names), and
 * with `updatePins` each pinned image tag under spec.values to the candidate
 * chart's default. Throws ChartEditError, with what was missing and where,
 * when any of it cannot be found or safely replaced.
 */
export function planChartEdits(
  files: Map<string, string>,
  opts: { namespace: string; name: string; toVersion: string; pins: PinnedImage[]; updatePins: boolean },
): ChartPlan {
  const hr = findDoc(files, "HelmRelease", opts.name, opts.namespace);
  const byPath = new Map<string, (Span & { object: string })[]>();
  const add = (d: FoundDoc, span: Span) => byPath.set(d.path, [...(byPath.get(d.path) ?? []), { ...span, object: objectId(d) }]);

  // The chart version.
  let version: VersionSite;
  const chartRef = hr.doc.getIn(["spec", "chartRef"]);
  if (chartRef !== undefined) {
    const kind = hr.doc.getIn(["spec", "chartRef", "kind"]);
    const refName = hr.doc.getIn(["spec", "chartRef", "name"]);
    const refNs = (hr.doc.getIn(["spec", "chartRef", "namespace"]) as string | undefined) ?? opts.namespace;
    if (kind !== "OCIRepository" || typeof refName !== "string") {
      throw new ChartEditError(`HelmRelease ${opts.namespace}/${opts.name} takes its chart from a ${String(kind)} chartRef; only OCIRepository is supported`);
    }
    const oci = findDoc(files, "OCIRepository", refName, refNs);
    if (oci.doc.getIn(["spec", "ref", "digest"]) !== undefined) {
      throw new ChartEditError(`OCIRepository ${refNs}/${refName} (${oci.path}) pins the chart by spec.ref.digest; tagamend does not resolve chart digests, so edit it by hand`);
    }
    // Flux prefers semver over tag when both are set.
    const field = oci.doc.getIn(["spec", "ref", "semver"]) !== undefined ? "semver" : oci.doc.getIn(["spec", "ref", "tag"]) !== undefined ? "tag" : null;
    if (!field) throw new ChartEditError(`OCIRepository ${refNs}/${refName} (${oci.path}) has no spec.ref.tag or spec.ref.semver; it follows latest, so there is no version to bump`);
    const { span, current } = planScalar(oci, files.get(oci.path)!, ["spec", "ref", field], opts.toVersion);
    add(oci, span);
    const sharedWith = findDocs(files, "HelmRelease")
      .filter((d) => !(d.path === hr.path && d.name === hr.name && d.namespace === hr.namespace) && d.doc.getIn(["spec", "chartRef", "kind"]) === "OCIRepository" && d.doc.getIn(["spec", "chartRef", "name"]) === refName)
      .filter((d) => ((d.doc.getIn(["spec", "chartRef", "namespace"]) as string | undefined) ?? d.namespace) === refNs)
      .map((d) => `${d.namespace ?? "?"}/${d.name}`);
    version = { kind: "OCIRepository", namespace: refNs, name: refName, path: oci.path, field: `spec.ref.${field}`, was: current, wasRange: !isExactVersion(current), sharedWith };
  } else {
    if (hr.doc.getIn(["spec", "chart", "spec"]) === undefined) {
      throw new ChartEditError(`HelmRelease ${opts.namespace}/${opts.name} (${hr.path}) has neither spec.chart.spec nor spec.chartRef`);
    }
    if (hr.doc.getIn(["spec", "chart", "spec", "version"]) === undefined) {
      throw new ChartEditError(`HelmRelease ${opts.namespace}/${opts.name} (${hr.path}) has no spec.chart.spec.version, so Flux installs the latest chart already; add a version line by hand to pin one`);
    }
    const { span, current } = planScalar(hr, files.get(hr.path)!, ["spec", "chart", "spec", "version"], opts.toVersion);
    add(hr, span);
    version = { kind: "HelmRelease", namespace: opts.namespace, name: opts.name, path: hr.path, field: "spec.chart.spec.version", was: current, wasRange: !isExactVersion(current), sharedWith: [] };
  }
  if (version.was === opts.toVersion) {
    throw new ChartEditError(`${version.kind} ${version.namespace}/${version.name} (${version.path}) already has ${version.field}: ${opts.toVersion}`);
  }

  // Pinned image tags.
  const pins: PinOutcome[] = [];
  for (const pin of opts.pins) {
    const target = pin.chartDefault?.tag ?? null;
    if (!opts.updatePins) {
      pins.push({ pin, outcome: "kept" });
      continue;
    }
    if (target === pin.pinnedTag) {
      pins.push({ pin, outcome: "same" });
      continue;
    }
    if (!target) {
      throw new ChartEditError(`the candidate chart's default tag for ${pin.kind}/${pin.name} is not known, so its pin at spec.values.${pin.valuesPath.join(".")} cannot move; open the PR without moving pins`);
    }
    const keyPath = ["spec", "values", ...pin.valuesPath];
    let planned: ReturnType<typeof planScalar>;
    try {
      planned = planScalar(hr, files.get(hr.path)!, keyPath, target);
    } catch (e) {
      if (e instanceof ChartEditError && /has no spec\.values/.test(e.message)) {
        throw new ChartEditError(`${e.message}. The pin for ${pin.kind}/${pin.name} may come from valuesFrom, which tagamend does not edit; open the PR without moving pins`);
      }
      throw e;
    }
    if (planned.current !== pin.pinnedTag) {
      throw new ChartEditError(
        `spec.values.${pin.valuesPath.join(".")} in ${hr.path} is \`${planned.current}\`, not the pinned \`${pin.pinnedTag}\` the chart sync recorded; wait for the next chart sync`,
      );
    }
    add(hr, planned.span);
    pins.push({ pin, outcome: "moved" });
  }

  const out = new Map<string, string>();
  const edits: ChartEdit[] = [];
  for (const [path, spans] of byPath) {
    const r = applySpans(path, files.get(path)!, spans);
    out.set(path, r.text);
    edits.push(...r.edits);
  }
  return { files: out, edits, version, pins };
}
