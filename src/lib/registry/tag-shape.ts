/**
 * Tag shape and ordering: which tags of an image count as newer versions of
 * the running tag.
 *
 * A tag is split into numeric and non-numeric runs. The numbers are wildcarded
 * to give its *shape*: `1.27.3-alpine` has the shape `N.N.N-alpine`. Two tags
 * are comparable only when their shapes are equal, and then they are ordered
 * by their numbers, left to right, as integers.
 *
 * A segment that looks like a git commit hash (`441d4ba` in
 * `master-372-441d4ba`) is replaced by `<sha>` before splitting. It is part of
 * the shape but never compared: the build counter before it carries the order.
 *
 * This is a heuristic and it is wrong for some images. Every chosen tag carries
 * a `reason` so that a wrong guess is visible.
 */

export interface ParsedTag {
  tag: string;
  /** The tag with each number replaced by `N` and each hash by `<sha>`. */
  shape: string;
  /** The numeric runs, left to right, with leading zeros removed. */
  numbers: string[];
  /** A non-numeric part names a prerelease: rc, alpha, beta, dev, nightly, pre... */
  prerelease: boolean;
  /**
   * `version`: has numbers, so it can be ordered.
   * `floating`: has no numbers (`latest`, `stable`, `main`): it has no order,
   * and the only question is whether its digest moved.
   */
  kind: "version" | "floating";
}

const SEPARATOR = /([-._+])/;
const PRERELEASE = /^(rc|alpha|beta|dev|nightly|pre|canary|snapshot|unstable)/i;

/** A git-style hash: 7 to 64 hex characters with at least one letter and one digit, or `g<hex>` from `git describe`. */
export function isShaLike(segment: string): boolean {
  const s = /^g[0-9a-f]{7,40}$/.test(segment) ? segment.slice(1) : segment;
  return /^[0-9a-f]{7,64}$/.test(s) && /[a-f]/.test(s) && /[0-9]/.test(s);
}

/**
 * A CI build tag, `<branch>-<counter>-<short sha>`, as Flux image policies
 * expect. The 7-character hash can be all digits (about 1 build in 27) or all
 * letters. isShaLike cannot call those a hash, but the position can, and
 * without this the tag's shape would differ from every other build's.
 */
const CI_BUILD = /^[a-z][\w.-]*-\d+-[0-9a-f]{7}$/i;

function stripZeros(n: string): string {
  const s = n.replace(/^0+/, "");
  return s === "" ? "0" : s;
}

export function parseTag(tag: string): ParsedTag {
  let shape = "";
  const numbers: string[] = [];
  const words: string[] = [];
  const segments = tag.split(SEPARATOR);
  const ciHash = CI_BUILD.test(tag) ? segments.length - 1 : -1;
  for (const [i, segment] of segments.entries()) {
    if (segment === "") continue;
    if (SEPARATOR.test(segment) && segment.length === 1) {
      shape += segment;
      continue;
    }
    if (i === ciHash || isShaLike(segment)) {
      shape += "<sha>";
      continue;
    }
    for (const run of segment.split(/(\d+)/)) {
      if (run === "") continue;
      if (/^\d+$/.test(run)) {
        shape += "N";
        numbers.push(stripZeros(run));
      } else {
        shape += run;
        words.push(run);
      }
    }
  }
  return {
    tag,
    shape,
    numbers,
    prerelease: words.some((w) => PRERELEASE.test(w)),
    kind: numbers.length > 0 ? "version" : "floating",
  };
}

/** Compares two non-negative integers written in decimal, of any length. */
function compareInt(a: string, b: string): number {
  if (a.length !== b.length) return a.length - b.length;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Orders two tags of the same shape by their numbers. Positive when `a` is
 * newer. Tags with different shapes are not comparable; this throws for them
 * rather than returning a misleading answer.
 */
export function compareTags(a: ParsedTag, b: ParsedTag): number {
  if (a.shape !== b.shape) throw new Error(`cannot compare ${a.tag} (${a.shape}) with ${b.tag} (${b.shape})`);
  for (let i = 0; i < a.numbers.length; i++) {
    const c = compareInt(a.numbers[i]!, b.numbers[i]!);
    if (c !== 0) return c;
  }
  return 0;
}

export interface Candidate {
  tag: string;
  reason: string;
}

export type Choice =
  | {
      mode: "version";
      shape: string;
      /** Newest first. */
      candidates: Candidate[];
      /** How many tags had the running tag's shape and sorted after it, before trimming. */
      newerCount: number;
    }
  | { mode: "floating" };

export const NEWEST_KEPT = 5;
/** At most this many "newest of a higher major" extras, highest majors first. */
export const MAJORS_KEPT = 10;

/**
 * Whether the first number behaves like a major version. Not when it is the
 * only number (`master-372-<sha>`: a build counter, every value is "a major"),
 * and not when it is longer than 4 digits (`20260903T183717Z`: a date).
 */
function hasMajor(p: ParsedTag): boolean {
  return p.numbers.length >= 2 && p.numbers[0]!.length <= 4;
}

/**
 * Chooses the candidate tags for one running tag from all of an image's tags.
 *
 * Kept: the newest 5 tags of the same shape that sort after the running tag;
 * the newest of each higher major (when the tag has one); and the newest in the
 * running tag's own line (same numbers except the last), which is the smallest
 * step forward and the one most likely to be a drop-in fix.
 */
export function chooseCandidates(running: string, tags: Iterable<string>): Choice {
  const r = parseTag(running);
  if (r.kind === "floating") return { mode: "floating" };

  const newer: ParsedTag[] = [];
  const seen = new Set<string>();
  for (const t of tags) {
    if (seen.has(t) || t === running) continue;
    seen.add(t);
    const p = parseTag(t);
    if (p.shape !== r.shape) continue;
    if (p.prerelease && !r.prerelease) continue;
    if (compareTags(p, r) <= 0) continue;
    newer.push(p);
  }
  // Newest first; equal numbers (only the hash differs) fall back to the tag text.
  newer.sort((a, b) => compareTags(b, a) || (a.tag < b.tag ? 1 : a.tag > b.tag ? -1 : 0));

  const reasons = new Map<string, string[]>();
  const add = (p: ParsedTag, why: string) => {
    const list = reasons.get(p.tag);
    if (list) list.push(why);
    else reasons.set(p.tag, [why]);
  };

  newer.slice(0, NEWEST_KEPT).forEach((p, i) =>
    add(p, `${i === 0 ? "newest" : `${ordinal(i + 1)} newest`} tag of shape ${r.shape} after ${running}`),
  );

  if (hasMajor(r)) {
    const runningMajor = r.numbers[0]!;
    const byMajor = new Map<string, ParsedTag>();
    for (const p of newer) {
      const m = p.numbers[0]!;
      if (compareInt(m, runningMajor) > 0 && !byMajor.has(m)) byMajor.set(m, p);
    }
    [...byMajor.entries()]
      .sort((a, b) => compareInt(b[0], a[0]))
      .slice(0, MAJORS_KEPT)
      .forEach(([m, p]) => add(p, `newest in major ${m}, above ${running}'s major ${runningMajor}`));

    const prefix = r.numbers.slice(0, -1);
    const line = newer.find((p) => prefix.every((n, i) => p.numbers[i] === n));
    if (line) add(line, `newest in ${running}'s own line (${prefix.join(".")}.*)`);
  }

  const candidates = newer
    .filter((p) => reasons.has(p.tag))
    .map((p) => ({ tag: p.tag, reason: reasons.get(p.tag)!.join("; ") }));
  return { mode: "version", shape: r.shape, candidates, newerCount: newer.length };
}

function ordinal(n: number): string {
  return ["", "1st", "2nd", "3rd"][n] ?? `${n}th`;
}
