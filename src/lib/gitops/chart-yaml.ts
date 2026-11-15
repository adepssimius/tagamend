import { type Document, isMap, isScalar, parseAllDocuments, parse as parseYaml, type Scalar, type YAMLMap } from "yaml";
import { kustomizeNamespace } from "./locate";

/**
 * Surgical edits to Flux objects for chart upgrades. Each file is parsed with
 * the `yaml` package only to find where a scalar sits (`node.range`, absolute
 * offsets into the file); the edit replaces exactly that span of text. Nothing
 * is re-serialised, so comments, quoting, key order and blank lines stay as
 * they are.
 */

/** One replaced scalar. Line-shaped like the tag PR's edits so pages show both the same way. */
export interface ChartEdit {
  path: string;
  /** 1-based. */
  line: number;
  before: string;
  after: string;
  /** Dotted path of the edited key inside its object, e.g. "spec.chart.spec.version". */
  field: string;
  /** "Kind/namespace/name" of the edited object. */
  object: string;
  /** Lines added rather than a value replaced: `line` is the line they follow, `after` the added lines. */
  added?: boolean;
}

/** A document found in the repo, with what is needed to edit it. */
export interface FoundDoc {
  path: string;
  doc: Document;
  kind: string;
  name: string;
  namespace: string | null;
}

/** A failure the PR queue reports as is: it names what was missing and where. */
export class ChartEditError extends Error {}

const META = (d: Document) => ({
  kind: str(d.get("kind")),
  name: str(d.getIn(["metadata", "name"])),
  namespace: str(d.getIn(["metadata", "namespace"])),
});
const str = (v: unknown) => (typeof v === "string" ? v : null);

/** Every YAML document of `kind` in the files, with its namespace resolved the way Kustomize would. */
export function findDocs(files: Map<string, string>, kind: string): FoundDoc[] {
  const out: FoundDoc[] = [];
  for (const [path, text] of files) {
    // Cheap pre-filter: most files never mention the kind.
    if (!text.includes(kind)) continue;
    for (const doc of parseAllDocuments(text)) {
      if (doc.errors.length || !isMap(doc.contents)) continue;
      const m = META(doc);
      if (m.kind !== kind || !m.name) continue;
      out.push({ path, doc, kind, name: m.name, namespace: m.namespace ?? kustomizeNamespace(files, path) });
    }
  }
  return out;
}

/** The one document of `kind` named `name` in `namespace`. Fails when there is none or more than one. */
export function findDoc(files: Map<string, string>, kind: string, name: string, namespace: string): FoundDoc {
  const all = findDocs(files, kind).filter((d) => d.name === name);
  let hits = all.filter((d) => d.namespace === namespace);
  // A document with no namespace anywhere above it is still ours when it is the only one by that name.
  if (hits.length === 0) hits = all.filter((d) => d.namespace == null);
  if (hits.length === 1) return hits[0]!;
  if (hits.length === 0) {
    const elsewhere = all.length ? ` (found in other namespaces: ${all.map((d) => `${d.namespace ?? "?"} in ${d.path}`).join(", ")})` : "";
    throw new ChartEditError(`no ${kind} ${namespace}/${name} in the repo${elsewhere}. It may be deployed from outside the repo.`);
  }
  throw new ChartEditError(`${kind} ${namespace}/${name} is defined more than once (${hits.map((d) => d.path).join(", ")}); edit it by hand`);
}

/** A version that names one release, not a range. */
export function isExactVersion(v: string): boolean {
  return /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/.test(v);
}

/**
 * The replacement text for a scalar, quoted the way the original was. A plain
 * scalar stays plain unless the new value would then read as something other
 * than the same string (a number such as `1.10`, `true`, `null`), in which case
 * it is double-quoted.
 */
function render(node: Scalar, value: string): string {
  if (node.type === "QUOTE_SINGLE") return `'${value.replace(/'/g, "''")}'`;
  if (node.type === "QUOTE_DOUBLE") return JSON.stringify(value);
  return plainOrQuoted(value);
}

/** `value` as a plain scalar when it reads back as the same string, else double-quoted. */
function plainOrQuoted(value: string): string {
  let plainOk = false;
  try {
    plainOk = parseYaml(value) === value && !/[:#]\s|^[\s&*!|>'"%@`{[\]},-]|\s$/.test(value);
  } catch {
    plainOk = false;
  }
  return plainOk ? value : JSON.stringify(value);
}

export interface Span {
  start: number;
  end: number;
  text: string;
  field: string;
  /** An insertion (start === end) of whole lines. */
  added?: boolean;
}

/**
 * Plans writes of string values at key paths in one document: a key that
 * exists is replaced in place (planScalar's rules); a missing one is added as
 * new lines under the deepest map that exists on its path, indented like that
 * map's own keys. Missing keys that share a parent are added together, so a
 * new map is written once. Fails when that parent is a flow map (`{}`), empty,
 * or not a map.
 */
export function planValueWrites(
  found: FoundDoc,
  source: string,
  writes: { path: (string | number)[]; value: string }[],
): { spans: Span[]; current: (string | null)[] } {
  const where = `${found.kind} ${found.namespace ?? "?"}/${found.name} (${found.path})`;
  const spans: Span[] = [];
  const current: (string | null)[] = [];
  type Tree = Map<string, Tree | string>;
  const inserts = new Map<number, { at: number; indent: string; tree: Tree; fields: string[] }>();
  for (const w of writes) {
    if (found.doc.getIn(w.path, true) !== undefined) {
      const r = planScalar(found, source, w.path, w.value);
      spans.push(r.span);
      current.push(r.current);
      continue;
    }
    // The deepest map on the path that exists.
    let depth = w.path.length - 1;
    let parent: unknown;
    while (depth > 0 && (parent = found.doc.getIn(w.path.slice(0, depth), true)) === undefined) depth--;
    if (depth === 0) parent = found.doc.contents;
    const field = w.path.slice(0, depth).join(".") || "(top level)";
    if (!isMap(parent)) throw new ChartEditError(`${where}: ${field} is not a map, so ${w.path.join(".")} cannot be added; edit it by hand`);
    const map = parent as YAMLMap;
    if (map.flow || map.items.length === 0) throw new ChartEditError(`${where}: ${field} is empty or written inline ({}), so ${w.path.join(".")} cannot be added; edit it by hand`);
    const firstKey = map.items[0]!.key as { range?: [number, number, number] } | null;
    const last = map.items[map.items.length - 1]!;
    const lastEnd = (last.value as { range?: [number, number, number] } | null)?.range?.[1] ?? (last.key as { range?: [number, number, number] }).range![1];
    if (!firstKey?.range) throw new ChartEditError(`${where}: cannot place a new key under ${field}; edit it by hand`);
    const keyStart = firstKey.range[0];
    const indent = source.slice(source.lastIndexOf("\n", keyStart - 1) + 1, keyStart);
    if (!/^ *$/.test(indent)) throw new ChartEditError(`${where}: ${field} is not a block map; edit it by hand`);
    let at = source[lastEnd - 1] === "\n" ? lastEnd - 1 : source.indexOf("\n", lastEnd);
    if (at === -1) at = source.length;
    let ins = inserts.get(keyStart);
    if (!ins) inserts.set(keyStart, (ins = { at, indent, tree: new Map(), fields: [] }));
    let node = ins.tree;
    const rest = w.path.slice(depth).map(String);
    for (const seg of rest.slice(0, -1)) {
      let next = node.get(seg);
      if (typeof next === "string") throw new ChartEditError(`${where}: ${w.path.join(".")} conflicts with another value written in this PR`);
      if (!next) node.set(seg, (next = new Map()));
      node = next;
    }
    node.set(rest[rest.length - 1]!, w.value);
    ins.fields.push(w.path.join("."));
    current.push(null);
  }
  const lines = (tree: Tree, indent: string): string[] =>
    [...tree].flatMap(([k, v]) => (typeof v === "string" ? [`${indent}${plainOrQuoted(k)}: ${plainOrQuoted(v)}`] : [`${indent}${plainOrQuoted(k)}:`, ...lines(v, indent + "  ")]));
  // Inserts at one offset are written deepest first, so each lands inside its own map.
  const byOffset = new Map<number, { indent: string; text: string; fields: string[] }[]>();
  for (const ins of inserts.values()) {
    byOffset.set(ins.at, [...(byOffset.get(ins.at) ?? []), { indent: ins.indent, text: lines(ins.tree, ins.indent).join("\n"), fields: ins.fields }]);
  }
  for (const [at, list] of byOffset) {
    list.sort((a, b) => b.indent.length - a.indent.length);
    spans.push({ start: at, end: at, text: list.map((l) => `\n${l.text}`).join(""), field: list.flatMap((l) => l.fields).join(", "), added: true });
  }
  return { spans, current };
}

/**
 * Plans a replacement of the scalar at `keyPath` in a document. Fails when the
 * key is absent, is not a single-line scalar, or uses an alias or a Flux
 * variable (`${...}`), since replacing those would change what they mean.
 */
export function planScalar(found: FoundDoc, source: string, keyPath: (string | number)[], value: string): { span: Span; current: string } {
  const field = keyPath.join(".");
  const where = `${found.kind} ${found.namespace ?? "?"}/${found.name} (${found.path})`;
  const node = found.doc.getIn(keyPath, true);
  if (node === undefined) throw new ChartEditError(`${where} has no ${field}`);
  if (!isScalar(node) || !node.range) throw new ChartEditError(`${where}: ${field} is not a plain value (an alias, list or map); edit it by hand`);
  if (node.type === "BLOCK_LITERAL" || node.type === "BLOCK_FOLDED") {
    throw new ChartEditError(`${where}: ${field} is a block scalar; edit it by hand`);
  }
  const [start, end] = node.range;
  const raw = source.slice(start, end);
  if (raw.includes("\n")) throw new ChartEditError(`${where}: ${field} spans several lines; edit it by hand`);
  // A plain scalar's source keeps what was written (`1.10`); its value may be a number (1.1).
  const current = typeof node.source === "string" ? node.source : String(node.value);
  if (current.includes("${")) {
    throw new ChartEditError(`${where}: ${field} is \`${current}\`, a Flux variable; set the variable's value where it is defined`);
  }
  if (/[\n\r]/.test(value)) throw new ChartEditError(`refusing a multi-line value for ${field}`);
  return { span: { start, end, text: render(node, value), field }, current };
}

/**
 * Applies spans to one file's text, last first so earlier offsets stay valid.
 * A scalar never spans lines, so the line count is unchanged and each edit's
 * line is the same before and after.
 */
export function applySpans(path: string, source: string, spans: (Span & { object: string })[]): { text: string; edits: ChartEdit[] } {
  const sorted = [...spans].sort((a, b) => b.start - a.start);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i]!.end > sorted[i - 1]!.start) throw new ChartEditError(`${path}: two edits overlap`);
  }
  let text = source;
  for (const s of sorted) text = text.slice(0, s.start) + s.text + text.slice(s.end);
  const before = source.split("\n");
  const lineOf = (off: number) => source.slice(0, off).split("\n").length;
  // Lines are numbered as in the base file; an addition follows its line.
  const edits = [...spans]
    .sort((a, b) => a.start - b.start)
    .map((s): ChartEdit => {
      const line = lineOf(s.start);
      if (s.added) return { path, line, before: "", after: s.text.replace(/^\n/, ""), field: s.field, object: s.object, added: true };
      // The edited line on its own: added lines elsewhere shift the new file's numbering.
      const lineStart = source.lastIndexOf("\n", s.start - 1) + 1;
      const lineEnd = source.indexOf("\n", s.end) === -1 ? source.length : source.indexOf("\n", s.end);
      const edited = source.slice(lineStart, s.start) + s.text + source.slice(s.end, lineEnd);
      return { path, line, before: before[line - 1]!, after: edited, field: s.field, object: s.object };
    });
  return { text, edits };
}
