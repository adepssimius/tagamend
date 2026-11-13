import type { ChartChangeDiff } from "../charts/diff";
import type { ChartImage } from "../charts/types";
import type { Chart } from "../db/schema";
import { type CveCounts, cveCounts } from "../queries/common";
import type { ChartPlan } from "./chart-edits";
import type { PrContent } from "./pr-body";

const fmt = (c: CveCounts) =>
  `${c.critical} critical, ${c.high} high, ${c.medium} medium` + (c.exploited ? `, of which **${c.exploited} known exploited**` : "");
const ref = (i: ChartImage) => `\`${i.registry}/${i.repository}:${i.tag ?? i.digest?.slice(0, 19) ?? "?"}\``;
const major = (v: string) => /^v?(\d+)\./.exec(v)?.[1] ?? null;

/** The chart version a PR moves from: what Flux installed, else what the repo says. */
export function fromVersion(chart: Chart, plan: ChartPlan): string {
  return chart.installed_version ?? plan.version.was;
}

/**
 * The text of a chart upgrade PR: where the version moves, the images the
 * candidate changes with the CVE diff for each, the pinned images and whether
 * this PR moves them, and what a version bump does not cover.
 */
export function buildChartPrContent(opts: {
  chart: Chart;
  toVersion: string;
  plan: ChartPlan;
  diffs: ChartChangeDiff[];
  /** CVE ids in CISA's Known Exploited Vulnerabilities catalog. */
  exploited: ReadonlySet<string>;
  chartUrl: string | null;
  requestedBy: string | null;
}): PrContent {
  const { chart, toVersion, plan } = opts;
  const from = fromVersion(chart, plan);
  const release = chart.name;
  const title = `${release}: bump chart ${chart.chart} ${from} to ${toVersion}`;
  const v = plan.version;
  const lines: string[] = [];

  lines.push(`Moves HelmRelease \`${chart.namespace}/${release}\` from chart \`${chart.chart}\` ${from} to ${toVersion} (\`${chart.source_url}\`).`);
  if (v.kind === "OCIRepository") {
    lines.push(
      "",
      `The chart comes from OCIRepository \`${v.namespace}/${v.name}\` through \`spec.chartRef\`, so the version lives there: this PR edits its \`${v.field}\` in \`${v.path}\`, not the HelmRelease.`,
    );
    if (v.sharedWith.length) {
      lines.push("", `**Shared source:** ${v.sharedWith.map((s) => `\`${s}\``).join(", ")} use the same OCIRepository and move to ${toVersion} too.`);
    }
  }
  if (v.wasRange) {
    lines.push("", `\`${v.field}\` was the range \`${v.was}\`. This PR pins it to \`${toVersion}\`, so Flux no longer picks up newer versions on its own.`);
  }

  // Images the candidate changes.
  lines.push("", "## Images this version changes", "");
  if (opts.diffs.length === 0) lines.push("None: the candidate renders the same images as the installed version.");
  let unscanned = 0;
  for (const d of opts.diffs) {
    const c = d.change;
    const head = `- **${c.kind}/${c.name}**`;
    if (!c.to) {
      lines.push(`${head}: ${ref(c.from!)} is dropped in ${toVersion}.`);
      continue;
    }
    lines.push(c.from ? `${head}: ${ref(c.from)} to ${ref(c.to)}` : `${head}: ${ref(c.to)}, new in ${toVersion}`);
    if (d.diff) {
      const counts = (vs: { vuln_id: string; severity: string }[]) => fmt(cveCounts(vs, opts.exploited));
      lines.push(
        `  - **Fixes:** ${counts(d.diff.fixed)}`,
        `  - **Still present:** ${counts(d.diff.stillPresent.map((s) => s.running))}`,
        `  - **New:** ${counts(d.diff.introduced)}`,
      );
    } else if (d.candidate) {
      lines.push(`  - Candidate image has ${fmt(d.candidate)}; nothing runs to compare it with.`);
    } else {
      unscanned++;
      lines.push(`  - Not scanned yet${d.scan && d.scan.status !== "done" ? ` (scan ${d.scan.status})` : ""}.`);
    }
  }
  if (unscanned) {
    lines.push("", `${unscanned} of these ${unscanned === 1 ? "image is" : "images are"} not scanned yet, so ${unscanned === 1 ? "its" : "their"} CVE change is unknown.${opts.chartUrl ? ` Scan from the chart page before merging.` : ""}`);
  }

  // Pinned images.
  if (plan.pins.length) {
    lines.push("", "## Pinned images", "", "These images are pinned with a `tag:` in the HelmRelease's values, so the chart version alone does not move them.", "");
    for (const { pin, outcome } of plan.pins) {
      const external = typeof pin.valuesPath[0] === "string" && pin.valuesPath[0].startsWith("valuesFrom:");
      const at = external
        ? `\`${pin.valuesPath.slice(1).join(".")}\` in the ${String(pin.valuesPath[0]).slice("valuesFrom:".length)} values`
        : `\`spec.values.${pin.valuesPath.join(".")}\``;
      const def = pin.chartDefault?.tag ? `\`${pin.chartDefault.tag}\`` : "unknown";
      const what =
        outcome === "moved"
          ? `this PR moves it to ${def}, the chart's default`
          : outcome === "same"
            ? "already the chart's default; left as is"
            : outcome === "external"
              ? `set outside this file, so this PR cannot move it; change it there to ${def} to follow the chart`
            : `left at \`${pin.pinnedTag}\`; the chart's default is ${def}`;
      lines.push(`- **${pin.kind}/${pin.name}** at ${at}: pinned to \`${pin.pinnedTag}\`, ${what}.`);
    }
  }

  lines.push("", "## Changes", "");
  for (const e of plan.edits) lines.push(`- \`${e.path}:${e.line}\` (\`${e.field}\`): \`${e.before.trim()}\` to \`${e.after.trim()}\``);

  const fromMajor = major(from);
  const toMajor = major(toVersion);
  const majorBump = fromMajor != null && toMajor != null && fromMajor !== toMajor;
  lines.push(
    "",
    "## Before merging",
    "",
    majorBump
      ? `**This is a major version bump (${fromMajor} to ${toMajor}).** Chart majors often need manual steps: renamed values, migrations, or objects to delete first. Read the chart's upgrade notes.`
      : "Chart releases can need manual steps, majors especially: renamed values, migrations, or objects to delete first. Read the chart's release notes between these versions.",
    "",
    "CRD changes are not covered. Whether Flux applies a chart's new CRDs depends on the HelmRelease's `install.crds` and `upgrade.crds` settings, and tagamend does not compare them.",
  );
  if (opts.chartUrl) lines.push("", `Chart page: ${opts.chartUrl}`);
  lines.push("", `Opened by tagamend${opts.requestedBy ? ` for ${opts.requestedBy}` : ""}.`);

  const moved = plan.pins.filter((p) => p.outcome === "moved").length;
  return {
    title,
    body: lines.join("\n"),
    commitMessage: `${title}\n\nEdits ${v.kind} ${v.namespace}/${v.name} ${v.field}${moved ? ` and moves ${moved} pinned image tag${moved === 1 ? "" : "s"} to the chart's defaults` : ""}.`,
  };
}
