/**
 * A HelmRelease's values, as Flux merges them: each valuesFrom source in order,
 * then spec.values on top. Each layer keeps where it came from, so a pinned
 * `tag:` key can be traced to the place a PR would edit.
 */

export type Values = Record<string, unknown>;

export interface ValuesLayer {
  /** "inline" for spec.values; otherwise "ConfigMap/<name>". */
  origin: string;
  values: Values;
}

export const isMap = (v: unknown): v is Values => v !== null && typeof v === "object" && !Array.isArray(v);

/** Helm's merge: maps merge key by key; anything else in `over` replaces. Inputs are not modified. */
export function deepMerge(base: Values, over: Values): Values {
  const out: Values = { ...base };
  for (const [k, v] of Object.entries(over)) {
    const b = out[k];
    out[k] = isMap(b) && isMap(v) ? deepMerge(b, v) : v;
  }
  return out;
}

export function mergeLayers(layers: ValuesLayer[]): Values {
  return layers.reduce<Values>((acc, l) => deepMerge(acc, l.values), {});
}

/**
 * A valuesFrom `targetPath` in the simple form `a.b.c`: the value is set at
 * that path. Flux also accepts Helm's --set syntax (list indexes, escaped
 * dots); those return null so the caller can say the source was skipped.
 */
export function valuesAtTargetPath(targetPath: string, value: string): Values | null {
  if (!/^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/.test(targetPath)) return null;
  const parts = targetPath.split(".");
  let out: unknown = value;
  for (const p of parts.reverse()) out = { [p]: out };
  return out as Values;
}

export interface TagKey {
  /** Path inside the merged values. */
  path: string[];
  value: string;
  /** The layer that set the value the merged values hold. */
  origin: string;
}

/** Every key named `tag` with a string value in the merged values, and which layer set it. */
export function findTagKeys(layers: ValuesLayer[]): TagKey[] {
  const merged = mergeLayers(layers);
  const out: TagKey[] = [];
  const walk = (v: unknown, path: string[]) => {
    if (!isMap(v)) return;
    for (const [k, child] of Object.entries(v)) {
      if (k === "tag" && typeof child === "string" && child !== "") {
        let origin = "inline";
        for (const l of layers) if (getAt(l.values, [...path, k]) !== undefined) origin = l.origin;
        out.push({ path: [...path, k], value: child, origin });
      } else walk(child, [...path, k]);
    }
  };
  walk(merged, []);
  return out;
}

export function getAt(values: unknown, path: string[]): unknown {
  let cur = values;
  for (const p of path) {
    if (!isMap(cur)) return undefined;
    cur = cur[p];
  }
  return cur;
}

/** A copy of `values` without the key at `path`. */
export function withoutKey(values: Values, path: string[]): Values {
  if (path.length === 0) return values;
  const [head, ...rest] = path as [string, ...string[]];
  if (!(head in values)) return values;
  const out = { ...values };
  if (rest.length === 0) delete out[head];
  else if (isMap(out[head])) out[head] = withoutKey(out[head], rest);
  return out;
}

/**
 * Paths of every `tag` key a chart could read for an image: each map that has
 * a `tag` key (any scalar or empty value), or a `repository` key with no tag
 * beside it. Walks the chart's default values merged with the HelmRelease's,
 * so keys the chart leaves empty (a tag that defaults to the app version) are
 * found too. Lists are not entered.
 */
export function findTagSlots(values: Values, limit = 64): string[][] {
  const out: string[][] = [];
  const walk = (v: unknown, path: string[]) => {
    if (!isMap(v) || out.length >= limit) return;
    const tag = v.tag;
    if ("tag" in v && (tag == null || typeof tag === "string" || typeof tag === "number")) out.push([...path, "tag"]);
    else if (typeof v.repository === "string" && !("tag" in v)) out.push([...path, "tag"]);
    for (const [k, child] of Object.entries(v)) if (k !== "tag") walk(child, [...path, k]);
  };
  walk(values, []);
  return out.slice(0, limit);
}

/** A copy of `values` with `value` set at `path`, creating maps on the way. */
export function setAt(values: Values, path: string[], value: unknown): Values {
  const [head, ...rest] = path as [string, ...string[]];
  const out = { ...values };
  out[head] = rest.length === 0 ? value : setAt(isMap(out[head]) ? out[head] : {}, rest, value);
  return out;
}
