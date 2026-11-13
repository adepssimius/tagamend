import { parseImageRef } from "../registry/hosts";
import { parseTag } from "../registry/tag-shape";

/** The Kubernetes object a reference sits in, read from its YAML document. */
export interface Owner {
  kind: string;
  name: string;
  /** From the object, else from the nearest kustomization.yaml's namespace:. */
  namespace: string | null;
}

export interface Edit {
  path: string;
  /** 1-based. */
  line: number;
  before: string;
  after: string;
  /** The running tag this line had. */
  fromTag: string;
  /** The object the line belongs to; a Kustomization for an images: entry. */
  owner: Owner | null;
}

export interface Skipped {
  path: string;
  line: number;
  text: string;
  reason: string;
  owner?: Owner | null;
}

export interface Target {
  /** As stored in `images`: `index.docker.io` for Docker Hub. */
  registry: string;
  repository: string;
  /** The tags the image runs with now. Only references to one of these move. */
  fromTags: string[];
  toTag: string;
  /**
   * Pin mode: keep the tag and pin it to this digest (`tag@sha256:...`). Used
   * when the candidate is the same tag at a newer digest, such as `stable`
   * after it moved. A digest pin makes the node pull that build; a moved tag
   * alone does not, when the node has the old one cached.
   */
  pinDigest?: string;
}

const IMAGE_LINE = /^(\s*(?:-\s+)?image:\s*)(["']?)([^\s"'#]+)\2(.*)$/;
const KEY_LINE = /^(\s*)(?:-\s+)?(registry|repository|tag):\s*(["']?)([^\s"'#]*)\3(.*)$/;
/** Flux image automation owns a line carrying a setter marker. */
const FLUX_MARKER = /\$imagepolicy/;

/**
 * Finds the references to an image in a set of YAML files and returns the
 * line edits that move them to `toTag`.
 *
 * Three forms are recognised:
 * - `image: <ref>` on one line (Deployments, StatefulSets, most chart values).
 *   A tag-less `image:` is not a reference to move: Kustomize or Flux sets
 *   its tag elsewhere.
 * - Helm-values blocks with `repository:` and `tag:` (and optionally
 *   `registry:`) as sibling keys at the same indent.
 * - Kustomize `images:` overrides in a kustomization.yaml: a `- name:` item
 *   with `newTag:` (and optionally `newName:`).
 *
 * A reference is moved only when its tag is one of `fromTags` and has the same
 * shape as `toTag`, so `1.27.3-alpine` never becomes `1.28.0`. Everything else
 * that names the image is reported in `skipped` with the reason, so a PR that
 * leaves something behind says what.
 */
export function findImageEdits(files: Map<string, string>, target: Target): { edits: Edit[]; skipped: Skipped[] } {
  const edits: Edit[] = [];
  const skipped: Skipped[] = [];
  const toShape = parseTag(target.toTag).shape;
  const same = (registry: string, repository: string) =>
    registry === target.registry && repository === target.repository;

  /** Decides one reference; returns the new tag or records why not. */
  const pin = target.pinDigest;
  const decide = (path: string, line: number, text: string, tag: string | null, digest: string | null): string | null => {
    const skip = (reason: string) => (skipped.push({ path, line, text: text.trim(), reason }), null);
    if (FLUX_MARKER.test(text)) return skip("Flux image automation manages this line");
    if (pin) {
      if (!tag) return skip("no tag");
      if (tag !== target.toTag) return skip(`tag ${tag} is not ${target.toTag}`);
      if (digest === pin) return skip(`already pinned to ${pin.slice(0, 19)}`);
      return target.toTag;
    }
    if (digest) return skip("pinned by digest");
    if (!tag) return skip("no tag");
    if (tag === target.toTag) return skip(`already ${target.toTag}`);
    if (!target.fromTags.includes(tag)) return skip(`tag ${tag} is not a running tag`);
    if (parseTag(tag).shape !== toShape) return skip(`tag ${tag} has a different shape from ${target.toTag}`);
    return target.toTag;
  };

  for (const [path, content] of [...files].sort(([a], [b]) => a.localeCompare(b))) {
    const lines = content.split("\n");
    lines.forEach((text, i) => {
      const m = IMAGE_LINE.exec(text);
      if (!m) return;
      const ref = parseImageRef(m[3]!);
      if (!same(ref.registry, ref.repository)) return;
      if (!ref.tag && !ref.digest) return; // tag set elsewhere (Kustomize images:, Flux)
      const to = decide(path, i + 1, text, ref.tag, ref.digest);
      if (!to) return;
      const raw = m[3]!;
      const noDigest = raw.includes("@") ? raw.slice(0, raw.indexOf("@")) : raw;
      const newRef = pin ? `${noDigest}@${pin}` : `${noDigest.slice(0, noDigest.length - ref.tag!.length)}${to}`;
      edits.push({ path, line: i + 1, before: text, after: `${m[1]}${m[2]}${newRef}${m[2]}${m[4]}`, fromTag: ref.tag!, owner: null });
    });

    // Split form: sibling keys in one mapping, found by matching indent.
    lines.forEach((text, i) => {
      const m = KEY_LINE.exec(text);
      if (!m || m[2] !== "repository") return;
      const indent = m[1]!.length + (text.trimStart().startsWith("-") ? 2 : 0);
      // The mapping this key belongs to: neighbouring lines indented at least as
      // far, stopping at the first line that is less indented (its parent).
      const indentOf = (l: string) => l.length - l.trimStart().length + (l.trimStart().startsWith("-") ? 2 : 0);
      const inBlock = (j: number) => {
        const l = lines[j]!;
        return l.trim() === "" || l.trimStart().startsWith("#") || indentOf(l) >= indent;
      };
      let lo = i;
      while (lo > 0 && inBlock(lo - 1) && !lines[lo]!.trimStart().startsWith("-")) lo--;
      let hi = i;
      while (hi < lines.length - 1 && inBlock(hi + 1) && !(indentOf(lines[hi + 1]!) === indent && lines[hi + 1]!.trimStart().startsWith("-"))) hi++;
      const siblings = new Map<string, { idx: number; value: string }>();
      for (let j = lo; j <= hi; j++) {
        const s = KEY_LINE.exec(lines[j]!);
        if (!s || indentOf(lines[j]!) !== indent) continue;
        if (!siblings.has(s[2]!)) siblings.set(s[2]!, { idx: j, value: s[4]! });
      }
      if (siblings.get("repository")?.idx !== i) return; // another repository key owns this block
      const repo = siblings.get("repository")!.value;
      const reg = siblings.get("registry")?.value;
      const ref = parseImageRef(reg ? `${reg}/${repo}` : repo);
      if (!same(ref.registry, ref.repository)) return;
      const tagLine = siblings.get("tag");
      if (!tagLine) {
        skipped.push({ path, line: i + 1, text: text.trim(), reason: "no tag key next to repository" });
        return;
      }
      const tagText = lines[tagLine.idx]!;
      if (pin) {
        skipped.push({ path, line: tagLine.idx + 1, text: tagText.trim(), reason: "Helm repository/tag values have no digest key to pin" });
        return;
      }
      const to = decide(path, tagLine.idx + 1, tagText, tagLine.value || null, null);
      if (!to) return;
      const after = tagText.replace(new RegExp(`(tag:\\s*["']?)${escapeRe(tagLine.value)}`), `$1${to}`);
      edits.push({ path, line: tagLine.idx + 1, before: tagText, after, fromTag: tagLine.value, owner: null });
    });

    if (/(^|\/)kustomization\.ya?ml$/.test(path)) {
      lines.forEach((text, i) => {
        const m = /^(\s*)-\s+name:\s*(["']?)([^\s"'#]+)\2/.exec(text);
        if (!m) return;
        const itemIndent = m[1]!.length + 2;
        const keys = new Map<string, { idx: number; value: string }>([["name", { idx: i, value: m[3]! }]]);
        for (let j = i + 1; j < lines.length; j++) {
          const l = lines[j]!;
          if (l.trim() === "" || l.trimStart().startsWith("#")) continue;
          const ind = l.length - l.trimStart().length;
          if (ind !== itemIndent || l.trimStart().startsWith("-")) break;
          const k = /^\s*(newName|newTag|digest):\s*(["']?)([^\s"'#]*)\2/.exec(l);
          if (k) keys.set(k[1]!, { idx: j, value: k[3]! });
        }
        if (!keys.has("newTag") && !keys.has("newName") && !keys.has("digest")) return; // not an images: entry
        const ref = parseImageRef(keys.get("newName")?.value ?? m[3]!);
        if (!same(ref.registry, ref.repository)) return;
        const newTag = keys.get("newTag");
        if (!newTag) {
          skipped.push({ path, line: i + 1, text: text.trim(), reason: keys.has("digest") ? "pinned by digest" : "no newTag" });
          return;
        }
        const tagText = lines[newTag.idx]!;
        const to = decide(path, newTag.idx + 1, tagText, newTag.value || null, keys.get("digest")?.value || null);
        if (!to) return;
        if (pin) {
          // Kustomize pins with a digest: key beside newTag.
          const d = keys.get("digest");
          if (d) {
            const dText = lines[d.idx]!;
            edits.push({ path, line: d.idx + 1, before: dText, after: dText.replace(d.value, pin), fromTag: newTag.value, owner: null });
          } else {
            const indent = tagText.slice(0, tagText.length - tagText.trimStart().length);
            edits.push({ path, line: newTag.idx + 1, before: tagText, after: `${tagText}\n${indent}digest: ${pin}`, fromTag: newTag.value, owner: null });
          }
          return;
        }
        const after = tagText.replace(new RegExp(`(newTag:\\s*["']?)${escapeRe(newTag.value)}`), `$1${to}`);
        edits.push({ path, line: newTag.idx + 1, before: tagText, after, fromTag: newTag.value, owner: null });
      });
    }
  }
  for (const e of edits) e.owner = ownerOf(files, e.path, e.line);
  for (const k of skipped) k.owner = ownerOf(files, k.path, k.line);
  return { edits, skipped };
}

/**
 * The object a line belongs to: the `kind` and `metadata.name`/`namespace` of
 * the YAML document (between `---` separators) that contains it. A namespace
 * the object does not set comes from the nearest kustomization.yaml above it.
 */
export function ownerOf(files: Map<string, string>, path: string, line: number): Owner | null {
  const lines = files.get(path)?.split("\n");
  if (!lines) return null;
  let start = line - 1;
  while (start > 0 && !/^---\s*$/.test(lines[start - 1]!)) start--;
  let end = line - 1;
  while (end < lines.length - 1 && !/^---\s*$/.test(lines[end + 1]!)) end++;
  let kind: string | null = null;
  let name: string | null = null;
  let namespace: string | null = null;
  let inMeta = false;
  for (let i = start; i <= end; i++) {
    const l = lines[i]!;
    const top = /^(\w+):\s*(["']?)([^\s"'#]*)\2/.exec(l);
    if (top) {
      inMeta = top[1] === "metadata";
      if (top[1] === "kind") kind = top[3]!;
      continue;
    }
    const meta = inMeta && /^ {2}(name|namespace):\s*(["']?)([^\s"'#]+)\2/.exec(l);
    if (meta) {
      if (meta[1] === "name" && !name) name = meta[3]!;
      if (meta[1] === "namespace" && !namespace) namespace = meta[3]!;
    }
  }
  // kind: is optional in a kustomization.yaml.
  if (!kind && /(^|\/)kustomization\.ya?ml$/.test(path)) kind = "Kustomization";
  if (!kind) return null;
  if (kind === "Kustomization" && !name) name = path.replace(/\/?kustomization\.ya?ml$/, "") || ".";
  if (!name) return null;
  if (!namespace) namespace = kustomizeNamespace(files, path);
  return { kind, name, namespace };
}

/** The namespace: of the nearest kustomization.yaml at or above a file's directory. */
export function kustomizeNamespace(files: Map<string, string>, path: string): string | null {
  const parts = path.split("/").slice(0, -1);
  for (let n = parts.length; n >= 0; n--) {
    const dir = parts.slice(0, n).join("/");
    for (const f of ["kustomization.yaml", "kustomization.yml"]) {
      const k = files.get(dir ? `${dir}/${f}` : f);
      const m = k && /^namespace:\s*(["']?)([^\s"'#]+)\1/m.exec(k);
      if (m) return m[2]!;
    }
  }
  return null;
}

/** Applies line edits to file contents; returns only the files that changed. */
export function applyEdits(files: Map<string, string>, edits: Edit[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const e of edits) {
    const lines = (out.get(e.path) ?? files.get(e.path)!).split("\n");
    if (lines[e.line - 1] !== e.before) throw new Error(`${e.path}:${e.line} changed since it was read`);
    lines[e.line - 1] = e.after;
    out.set(e.path, lines.join("\n"));
  }
  return out;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
