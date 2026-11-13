import { parseAllDocuments } from "yaml";
import { parseImageRef } from "../registry/hosts";
import type { ChartImage, ChartImageChange } from "./types";

/** A reference a runtime would accept: [host/]path[:tag][@digest], lower-case path. */
const PATH_COMPONENT = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
const REF = new RegExp(
  `^(?:[A-Za-z0-9.-]+(?::\\d+)?/)?${PATH_COMPONENT}(?:/${PATH_COMPONENT})*(?::[\\w][\\w.-]{0,127})?(?:@[a-z0-9]+:[a-f0-9]{32,})?$`,
);

export function looksLikeImageRef(s: string): boolean {
  return s.length <= 512 && REF.test(s.trim());
}

/** A rendered image reference as a ChartImage, or null when it is not one. */
export function toChartImage(key: string, kind: string, name: string, ref: string): ChartImage | null {
  if (!looksLikeImageRef(ref)) return null;
  const r = parseImageRef(ref);
  return { key, kind, name, ref: ref.trim(), registry: r.registry, repository: r.repository, tag: r.tag, digest: r.digest };
}

/**
 * Every image in a multi-document render: each string under a key named
 * `image`, in any kind of object (workloads, and operator CRs such as a
 * CephCluster's spec.cephVersion.image). Keyed by object and field path, which
 * stays the same between versions of a chart.
 */
export function extractImages(rendered: string): ChartImage[] {
  const out = new Map<string, ChartImage>();
  for (const doc of parseAllDocuments(rendered)) {
    if (doc.errors.length) throw new Error(`rendered YAML does not parse: ${doc.errors[0]!.message}`);
    const o = doc.toJS({ maxAliasCount: -1 }) as Record<string, unknown> | null;
    if (!o || typeof o !== "object" || Array.isArray(o)) continue;
    const kind = typeof o.kind === "string" ? o.kind : "";
    const meta = o.metadata as { name?: unknown } | undefined;
    const name = typeof meta?.name === "string" ? meta.name : "";
    if (!kind || !name) continue;
    const walk = (v: unknown, path: string) => {
      if (Array.isArray(v)) v.forEach((c, i) => walk(c, `${path}[${i}]`));
      else if (v && typeof v === "object") {
        for (const [k, c] of Object.entries(v)) {
          const p = path ? `${path}.${k}` : k;
          if (k === "image" && typeof c === "string") {
            const key = `${kind}/${name}:${p}`;
            const img = toChartImage(key, kind, name, c);
            if (img && !out.has(key)) out.set(key, img);
          } else walk(c, p);
        }
      }
    };
    walk(o, "");
  }
  return [...out.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/** Images whose reference differs between two renders, plus those only one has. */
export function diffImages(current: ChartImage[], candidate: ChartImage[]): ChartImageChange[] {
  const from = new Map(current.map((i) => [i.key, i]));
  const to = new Map(candidate.map((i) => [i.key, i]));
  const keys = [...new Set([...from.keys(), ...to.keys()])].sort();
  const out: ChartImageChange[] = [];
  for (const key of keys) {
    const f = from.get(key) ?? null;
    const t = to.get(key) ?? null;
    if (f && t && f.ref === t.ref) continue;
    const any = (t ?? f)!;
    out.push({ key, kind: any.kind, name: any.name, from: f, to: t });
  }
  return out;
}
