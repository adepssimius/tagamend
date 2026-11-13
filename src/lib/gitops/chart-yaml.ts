import { type Document, isMap, isScalar, parseAllDocuments, parse as parseYaml, type Scalar } from "yaml";
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
  const after = text.split("\n");
  const lineOf = (off: number) => source.slice(0, off).split("\n").length;
  const edits = [...spans]
    .sort((a, b) => a.start - b.start)
    .map((s) => {
      const line = lineOf(s.start);
      return { path, line, before: before[line - 1]!, after: after[line - 1]!, field: s.field, object: s.object };
    });
  return { text, edits };
}
