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

function countBy(vs: Vulnerability[]): string {
  const ids = (s: string) => new Set(vs.filter((v) => v.severity === s).map((v) => v.vuln_id)).size;
  return SEVERITIES.map((s) => `${ids(s)} ${s.toLowerCase()}`).join(", ");
}

function list(vs: Vulnerability[]): string {
  const seen = new Set<string>();
  const rows: string[] = [];
  for (const v of vs) {
    if (v.severity !== "CRITICAL" && v.severity !== "HIGH") continue;
    if (seen.has(v.vuln_id)) continue;
    seen.add(v.vuln_id);
    rows.push(`| ${v.severity} | [${v.vuln_id}](https://osv.dev/vulnerability/${v.vuln_id}) | \`${v.package}\` | ${(v.title ?? "").replace(/\|/g, "\\|").slice(0, 90)} |`);
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
}): PrContent {
  const app = opts.repository.split("/").pop()!;
  const from = opts.fromTags.join(", ");
  const title = `${app}: bump ${from} to ${opts.toTag}`;
  const { fixed, stillPresent, introduced } = opts.diff;
  const upstream = stillPresent.filter((s) => s.fixAvailableUpstream).length;

  const lines: string[] = [];
  lines.push(
    `Moves \`${opts.registry}/${opts.repository}\` from \`${from}\` to \`${opts.toTag}\` (\`${opts.toDigest.slice(0, 19)}\`).`,
  );
  lines.push("");
  lines.push("## What the candidate scan shows");
  lines.push("");
  lines.push(`- **Fixes:** ${countBy(fixed)}`);
  lines.push(`- **Still present:** ${countBy(stillPresent.map((s) => s.running))}${upstream ? `. ${upstream} of these have a fix upstream that ${opts.toTag} does not include yet.` : ""}`);
  lines.push(`- **New in ${opts.toTag}:** ${countBy(introduced)}`);
  if (opts.scanUrl) lines.push(`\nFull diff: ${opts.scanUrl}`);
  const fixedList = list(fixed);
  if (fixedList) lines.push("", "### Critical and high fixed", "", fixedList);
  const newList = list(introduced);
  if (newList) lines.push("", `### Critical and high new in ${opts.toTag}`, "", newList);

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
