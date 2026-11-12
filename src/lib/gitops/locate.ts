import { parseImageRef } from "../registry/hosts";
import { parseTag } from "../registry/tag-shape";

export interface Edit {
  path: string;
  /** 1-based. */
  line: number;
  before: string;
  after: string;
  /** The running tag this line had. */
  fromTag: string;
}

export interface Skipped {
  path: string;
  line: number;
  text: string;
  reason: string;
}

export interface Target {
  /** As stored in `images`: `index.docker.io` for Docker Hub. */
  registry: string;
  repository: string;
  /** The tags the image runs with now. Only references to one of these move. */
  fromTags: string[];
  toTag: string;
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
  const decide = (path: string, line: number, text: string, tag: string | null, digest: string | null): string | null => {
    const skip = (reason: string) => (skipped.push({ path, line, text: text.trim(), reason }), null);
    if (FLUX_MARKER.test(text)) return skip("Flux image automation manages this line");
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
      const newRef = `${raw.slice(0, raw.length - ref.tag!.length)}${to}`;
      edits.push({ path, line: i + 1, before: text, after: `${m[1]}${m[2]}${newRef}${m[2]}${m[4]}`, fromTag: ref.tag! });
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
      const to = decide(path, tagLine.idx + 1, tagText, tagLine.value || null, null);
      if (!to) return;
      const after = tagText.replace(new RegExp(`(tag:\\s*["']?)${escapeRe(tagLine.value)}`), `$1${to}`);
      edits.push({ path, line: tagLine.idx + 1, before: tagText, after, fromTag: tagLine.value });
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
        const after = tagText.replace(new RegExp(`(newTag:\\s*["']?)${escapeRe(newTag.value)}`), `$1${to}`);
        edits.push({ path, line: newTag.idx + 1, before: tagText, after, fromTag: newTag.value });
      });
    }
  }
  return { edits, skipped };
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
