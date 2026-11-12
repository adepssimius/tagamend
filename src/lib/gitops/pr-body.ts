import type { Vulnerability } from "../db/schema";
import type { Diff } from "../trivy/diff";
import type { Edit, Skipped } from "./locate";

export interface PrContent {
  title: string;
  body: string;
  commitMessage: string;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"] as const;
const LISTED = 25;

function countBy(vs: Vulnerability[], exploited: Set<string> = new Set()): string {
  const ids = (s: string) => new Set(vs.filter((v) => v.severity === s).map((v) => v.vuln_id)).size;
  const kev = new Set(vs.map((v) => v.vuln_id).filter((id) => exploited.has(id))).size;
  return SEVERITIES.map((s) => `${ids(s)} ${s.toLowerCase()}`).join(", ") + (kev ? `, of which **${kev} known exploited**` : "");
}

function list(vs: Vulnerability[], exploited: Set<string>): string {
  const seen = new Set<string>();
  const rows: string[] = [];
  for (const v of vs) {
    if (v.severity !== "CRITICAL" && v.severity !== "HIGH" && !exploited.has(v.vuln_id)) continue;
    if (seen.has(v.vuln_id)) continue;
    seen.add(v.vuln_id);
    const flag = exploited.has(v.vuln_id) ? " **exploited**" : "";
    rows.push(`| ${v.severity} | [${v.vuln_id}](https://osv.dev/vulnerability/${v.vuln_id})${flag} | \`${v.package}\` | ${(v.title ?? "").replace(/\|/g, "\\|").slice(0, 90)} |`);
  }
  if (rows.length === 0) return "";
  const more = rows.length > LISTED ? `\n\n${rows.length - LISTED} more on the scan page.` : "";
  return `| Severity | CVE | Package | Title |\n|---|---|---|---|\n${rows.slice(0, LISTED).join("\n")}${more}`;
}

/**
 * The PR text: what moves, what the candidate scan says it fixes and adds,
 * and anything that names the image but was left alone.
 */
export function buildPrContent(opts: {
  repository: string;
  registry: string;
  fromTags: string[];
  toTag: string;
  toDigest: string;
  diff: Diff<Vulnerability>;
  edits: Edit[];
  skipped: Skipped[];
  scanUrl: string | null;
  requestedBy: string | null;
  /** CVE ids in CISA's Known Exploited Vulnerabilities catalog. */
  exploited?: Set<string>;
  /** The tag stays; the PR pins it to `toDigest`. */
  pinned?: boolean;
  /** Only these workloads move ("namespace/name"); others keep their tag. */
  onlyWorkloads?: string[];
}): PrContent {
  const exploited = opts.exploited ?? new Set<string>();
  const app = opts.repository.split("/").pop()!;
  const from = opts.fromTags.join(", ");
  const short = opts.toDigest.replace(/^sha256:/, "").slice(0, 12);
  const scope = opts.onlyWorkloads?.length ? ` (${opts.onlyWorkloads.join(", ")})` : "";
  const title = opts.pinned ? `${app}${scope}: pin ${opts.toTag} to ${short}` : `${app}${scope}: bump ${from} to ${opts.toTag}`;
  const { fixed, stillPresent, introduced } = opts.diff;
  const upstream = stillPresent.filter((s) => s.fixAvailableUpstream).length;

  const lines: string[] = [];
  lines.push(
    opts.pinned
      ? `Pins \`${opts.registry}/${opts.repository}:${opts.toTag}\` to \`${opts.toDigest}\`, the build the tag points to now. The running pods are on an older build of the same tag. A digest pin makes the next rollout pull this build; a restart alone reuses a cached \`${opts.toTag}\` on nodes that have one.`
      : `Moves \`${opts.registry}/${opts.repository}\` from \`${from}\` to \`${opts.toTag}\` (\`${opts.toDigest.slice(0, 19)}\`).`,
  );
  if (opts.onlyWorkloads?.length) {
    lines.push("", `Only ${opts.onlyWorkloads.map((w) => `\`${w}\``).join(", ")}. Other workloads of this image keep their current tag.`);
  }
  lines.push("");
  lines.push("## What the candidate scan shows");
  lines.push("");
  lines.push(`- **Fixes:** ${countBy(fixed, exploited)}`);
  lines.push(`- **Still present:** ${countBy(stillPresent.map((s) => s.running), exploited)}${upstream ? `. ${upstream} of these have a fix upstream that ${opts.toTag} does not include yet.` : ""}`);
  lines.push(`- **New in ${opts.toTag}:** ${countBy(introduced, exploited)}`);
  if (opts.scanUrl) lines.push(`\nFull diff: ${opts.scanUrl}`);
  const fixedList = list(fixed, exploited);
  if (fixedList) lines.push("", "### Critical, high, and exploited fixed", "", fixedList);
  const newList = list(introduced, exploited);
  if (newList) lines.push("", `### Critical, high, and exploited new in ${opts.toTag}`, "", newList);

  lines.push("", "## Changes", "");
  for (const e of opts.edits) lines.push(`- \`${e.path}:${e.line}\``);
  if (opts.skipped.length) {
    lines.push("", "### Left alone", "");
    for (const s of opts.skipped) lines.push(`- \`${s.path}:${s.line}\`: ${s.reason}`);
  }
  lines.push(
    "",
    "## Before merging",
    "",
    "The scan covers CVEs only. Read the release notes between these versions for breaking changes and migrations.",
    "",
    `Opened by tagamend${opts.requestedBy ? ` for ${opts.requestedBy}` : ""}.`,
  );

  return {
    title,
    body: lines.join("\n"),
    commitMessage: `${title}\n\nFixes ${countBy(fixed)}; adds ${countBy(introduced)}, per a Trivy scan of ${opts.toDigest}.`,
  };
}
