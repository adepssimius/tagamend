import Link from "next/link";
import { notFound } from "next/navigation";
import { requireUser } from "@/auth";
import { SubmitButton } from "@/components/submit-button";
import { Ago, Empty, ErrorText, linkClass, mutedClass, ScanStatusBadge, Section, SeverityCount, ShortDigest, Table } from "@/components/ui";
import type { ChartChangeDiff } from "@/lib/charts/diff";
import type { ChartImage } from "@/lib/charts/types";
import { getConfig } from "@/lib/config";
import { getDb } from "@/lib/db";
import type { CveCounts } from "@/lib/queries/common";
import { type ChartCandidateRow, type ChartPage as ChartPageData, getChartPage } from "@/lib/queries/charts";
import { diffSummary } from "@/lib/trivy/diff";
import { ChartPrState, ChartScanState, Delta, Exploited, SourceName } from "../components";
import { refreshChartPrStates } from "@/lib/gitops/pr-state";
import { checkChartNow, openChartPullRequest, scanChartCandidate } from "./actions";

export const dynamic = "force-dynamic";

type SP = Record<string, string | string[] | undefined>;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) || undefined;

export default async function ChartPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<SP> }) {
  await requireUser();
  const { id } = await params;
  const sp = await searchParams;
  const chartId = Number(id);
  if (!Number.isInteger(chartId)) notFound();
  const candidateParam = Number(one(sp.candidate));
  const db = await getDb();
  const config = getConfig();
  // On demand: an open PR's state is read from GitHub as the page loads.
  await refreshChartPrStates(db, { repo: config.GITOPS_REPO, token: config.GITHUB_READ_TOKEN, chartId });
  const page = await getChartPage(db, chartId, Number.isInteger(candidateParam) ? candidateParam : undefined);
  if (!page) notFound();
  const { chart, workloads, running, currentImages, candidates, others, selected } = page;
  const prsEnabled = !!config.GITOPS_REPO;
  const prError = one(sp.prError);
  const workloadCount = new Set(workloads.map((w) => `${w.kind}/${w.name}`)).size;

  return (
    <div>
      <h1 className="text-lg">
        <span className={mutedClass}>{chart.namespace}/</span>
        <span className="font-semibold">{chart.name}</span>
        {chart.gone_at && <span className={`ml-2 text-xs ${mutedClass}`}>gone</span>}
      </h1>
      <p className="mt-0.5 text-xs">
        <span className="font-mono">{chart.chart}</span>
        <span className={mutedClass}> from {chart.source_kind} </span>
        <SourceName url={chart.source_url} />
      </p>

      <dl className="mt-3 grid grid-cols-2 gap-px overflow-hidden rounded border border-zinc-200 bg-zinc-200 text-sm sm:grid-cols-7 dark:border-zinc-800 dark:bg-zinc-800">
        {(
          [
            ["Written", <span key="v" className="font-mono text-base">{chart.version}</span>],
            ["Installed", <span key="i" className="font-mono text-base">{chart.installed_version ?? "—"}</span>],
            ["Workloads", workloadCount],
            ["Critical", <SeverityCount key="c" severity="CRITICAL" n={running.critical} />],
            ["High", <SeverityCount key="h" severity="HIGH" n={running.high} />],
            ["Medium", <SeverityCount key="m" severity="MEDIUM" n={running.medium} />],
            ["Known exploited", <Exploited key="k" n={running.exploited} />],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="min-w-0 bg-white px-3 py-2 dark:bg-zinc-950">
            <dt className={`text-xs ${mutedClass}`}>{label}</dt>
            <dd className="truncate text-lg font-semibold tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      <div className={`mt-1 text-xs ${mutedClass}`}>
        CVEs in the images this HelmRelease runs now, counted per image and added up. Last check:{" "}
        {chart.last_sync_at ? <Ago iso={chart.last_sync_at} /> : "due, within a minute"}
        {chart.last_sync_at && (
          <form action={checkChartNow} className="ml-2 inline">
            <input type="hidden" name="chartId" value={chart.id} />
            <button type="submit" className={`${linkClass} text-xs`}>
              check now
            </button>
          </form>
        )}
      </div>

      {chart.sync_error && (
        <div className="mt-2 rounded border border-red-200 bg-red-50 px-3 py-2 dark:border-red-900 dark:bg-red-950/40">
          <p className="text-xs font-medium text-red-800 dark:text-red-300">Chart check failed</p>
          <ErrorText>{chart.sync_error}</ErrorText>
        </div>
      )}
      {chart.render_note && (
        <div className="mt-2 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs dark:border-amber-800 dark:bg-amber-950/40">
          <p className="font-medium text-amber-900 dark:text-amber-200">Render note</p>
          <p className="mt-0.5 whitespace-pre-wrap text-amber-900/80 dark:text-amber-200/80">{chart.render_note}</p>
        </div>
      )}

      <Section title="Current images" count={currentImages.length} note="What the installed version renders with this HelmRelease's values.">
        {currentImages.length === 0 ? (
          <Empty>{chart.last_sync_at ? "The installed version renders no images." : "Not rendered yet."}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Object</th>
                <th>Field</th>
                <th>Image</th>
              </tr>
            </thead>
            <tbody>
              {currentImages.map((i) => (
                <tr key={i.key}>
                  <td>
                    <span className={mutedClass}>{i.kind}/</span>
                    {i.name}
                  </td>
                  <td className={`font-mono text-xs ${mutedClass}`}>{fieldOf(i.key)}</td>
                  <td className="break-all font-mono text-xs">
                    {i.imageId != null ? (
                      <Link href={`/images/${i.imageId}`} className={linkClass}>
                        {i.ref}
                      </Link>
                    ) : (
                      i.ref
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="Candidate versions" count={candidates.length}>
        {candidates.length === 0 ? (
          <Empty>
            {chart.sync_error
              ? "The last check failed, so there may be newer versions."
              : chart.last_sync_at
                ? "No newer versions found."
                : "Not checked yet. The chart check runs every minute."}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Version</th>
                <th>App version</th>
                <th>Why</th>
                <th>First seen</th>
                <th>Images</th>
                <th>Scans</th>
                {prsEnabled && <th>PR</th>}
              </tr>
            </thead>
            <tbody>
              {candidates.map((c) => {
                const isSelected = selected?.candidate.id === c.candidate.id;
                return (
                  <tr key={c.candidate.id} className={isSelected ? "bg-blue-50/60 dark:bg-blue-950/30" : undefined}>
                    <td className="font-mono text-xs">
                      <Link href={`/charts/${chart.id}?candidate=${c.candidate.id}#candidate`} className={linkClass}>
                        {c.candidate.version}
                      </Link>
                    </td>
                    <td className="font-mono text-xs">{c.candidate.app_version ?? <span className={mutedClass}>—</span>}</td>
                    <td className={`text-xs ${mutedClass}`}>{c.candidate.reason ?? "—"}</td>
                    <td>
                      <Ago iso={c.candidate.first_seen_at} />
                    </td>
                    <td className="text-xs">
                      <ImagesChanged row={c} />
                    </td>
                    <td>
                      <ChartScanState state={c} />
                    </td>
                    {prsEnabled && (
                      <td>
                        <div className="space-y-0.5">
                          {c.prs.map((p) => (
                            <ChartPrState key={p.id} pr={p} short />
                          ))}
                        </div>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
        {others.length > 0 && (
          <details className="mt-2 text-xs">
            <summary className={`cursor-pointer ${mutedClass}`}>
              {others.length} {others.length === 1 ? "version" : "versions"} not a candidate
            </summary>
            <ul className="mt-1 space-y-0.5">
              {others.map((c) => (
                <li key={c.id}>
                  <span className="font-mono">{c.version}</span>
                  {c.reason && <span className={`ml-2 ${mutedClass}`}>{c.reason}</span>}
                </li>
              ))}
            </ul>
          </details>
        )}
      </Section>

      {selected && <CandidateDetail chartId={chart.id} row={selected} prsEnabled={prsEnabled} prError={prError} />}
    </div>
  );
}

/** The field path part of an image key: "Deployment/x:spec.template..." → "spec.template...". */
const fieldOf = (key: string) => key.slice(key.indexOf(":") + 1);

function ImagesChanged({ row }: { row: ChartCandidateRow }) {
  if (row.candidate.render_error) return <span className="text-red-700 dark:text-red-400">render failed</span>;
  if (!row.candidate.rendered_at) return <span className={mutedClass}>not rendered yet</span>;
  if (row.changed === 0) return <span className={mutedClass}>same images</span>;
  return (
    <span>
      {row.changed} {row.changed === 1 ? "image changes" : "images change"}
      {row.pinned.length > 0 && <span className={mutedClass}> · {row.pinned.length} pinned</span>}
    </span>
  );
}

function CandidateDetail({
  chartId,
  row,
  prsEnabled,
  prError,
}: {
  chartId: number;
  row: NonNullable<ChartPageData["selected"]>;
  prsEnabled: boolean;
  prError: string | undefined;
}) {
  const c = row.candidate;
  const pinTargets = row.pins.filter((p) => p.pin.chartDefault?.digest).length;
  // Something left to scan: a target with no scan, or a failed one.
  const toScan =
    row.diffs.some((d) => d.change.to?.digest && (!d.scan || d.scan.status === "failed")) ||
    row.pins.some((p) => p.pin.chartDefault?.digest && (!p.diff?.scan || p.diff.scan.status === "failed"));
  const anyScanned = row.diffs.some((d) => d.scan?.status === "done") || row.pins.some((p) => p.diff?.scan?.status === "done");
  const openPr = row.prs.find((p) => p.status !== "failed" && (p.pr_state == null || p.pr_state === "open" || p.pr_state === "draft"));
  const canOpenPr = prsEnabled && !!c.rendered_at && !c.render_error && !openPr;

  return (
    <section id="candidate" className="mt-8 rounded border border-zinc-200 p-3 dark:border-zinc-800">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-sm font-semibold">
          Version <span className="font-mono">{c.version}</span>
          {c.app_version && <span className={`ml-2 font-normal ${mutedClass}`}>app {c.app_version}</span>}
          {!c.is_candidate && <span className={`ml-2 text-xs font-normal ${mutedClass}`}>not a candidate</span>}
        </h2>
        <p className={`text-xs ${mutedClass}`}>
          {c.reason}
          {c.rendered_at && (
            <>
              {c.reason && " · "}rendered <Ago iso={c.rendered_at} />
            </>
          )}
        </p>
      </div>
      {c.render_error && (
        <div className="mt-2">
          <p className="text-xs font-medium text-red-800 dark:text-red-300">Render failed</p>
          <ErrorText>{c.render_error}</ErrorText>
        </div>
      )}

      <div className="mt-3 flex flex-wrap items-start gap-4">
        {(row.scannable > 0 || pinTargets > 0) && (
          <div>
            {toScan ? (
              <form action={scanChartCandidate}>
                <input type="hidden" name="candidateId" value={c.id} />
                <SubmitButton pendingText="Queuing…">{anyScanned ? "Scan the rest" : "Scan images"}</SubmitButton>
              </form>
            ) : (
              <span className={`text-xs ${mutedClass}`}>All images are queued or scanned.</span>
            )}
          </div>
        )}
        {prsEnabled && (
          <div className="space-y-1">
            {row.prs.map((p) => (
              <div key={p.id} className="flex flex-wrap items-center gap-1.5 text-xs">
                <ChartPrState pr={p} />
                {p.update_pins === 1 && <span className={mutedClass}>moves pinned tags</span>}
                {p.requested_by && (
                  <span className={mutedClass}>
                    · {p.requested_by}, <Ago iso={p.requested_at} />
                  </span>
                )}
              </div>
            ))}
            {canOpenPr && (
              <form action={openChartPullRequest} className="space-y-1">
                <input type="hidden" name="candidateId" value={c.id} />
                {row.pinned.length > 0 && (
                  <label className="flex items-center gap-1.5 text-xs">
                    <input type="checkbox" name="updatePins" value="1" />
                    Also move pinned tags to the chart&apos;s defaults
                  </label>
                )}
                <SubmitButton pendingText="Queuing…">{row.prs.some((p) => p.status === "failed") ? "Retry PR" : "Open PR"}</SubmitButton>
                {row.state !== "all" && row.state !== "n/a" && (
                  <p className={`text-xs ${mutedClass}`}>Not every image is scanned yet.</p>
                )}
              </form>
            )}
            {prError && (
              <div className="rounded border border-red-200 bg-red-50 px-2 py-1 dark:border-red-900 dark:bg-red-950/40">
                <p className="text-xs font-medium text-red-800 dark:text-red-300">Could not queue the PR</p>
                <ErrorText>{prError}</ErrorText>
              </div>
            )}
          </div>
        )}
      </div>

      <h3 className="mt-4 text-xs font-semibold">
        Images this version changes <span className={`font-normal ${mutedClass}`}>{row.diffs.length}</span>
      </h3>
      <p className={`text-xs ${mutedClass}`}>
        Counts are for the new image once scanned, with the change against what runs now. &quot;now&quot; is the running
        image.
      </p>
      <div className="mt-1">
        {row.diffs.length === 0 ? (
          <Empty>{c.rendered_at ? "This version runs the same images." : "Not rendered yet."}</Empty>
        ) : (
          <ImageTable
            rows={row.diffs.map((d) => ({
              key: d.change.key,
              kind: d.change.kind,
              name: d.change.name,
              from: d.change.from,
              to: d.change.to,
              d,
            }))}
          />
        )}
      </div>

      {row.pins.length > 0 && (
        <>
          <h3 className="mt-4 text-xs font-semibold">
            Pinned images <span className={`font-normal ${mutedClass}`}>{row.pins.length}</span>
          </h3>
          <p className={`text-xs ${mutedClass}`}>
            The values set these tags, so the chart bump does not change them. Tick &quot;Also move pinned tags&quot; to
            move them to the chart&apos;s defaults in the same PR.
          </p>
          <div className="mt-1 space-y-1">
            {row.pins.map(({ pin }) => (
              <p key={pin.key} className="text-xs">
                <span className={mutedClass}>{pin.kind}/</span>
                {pin.name}: values pin tag <span className="font-mono">{pin.pinnedTag}</span>
                {pin.chartDefault ? (
                  <>
                    ; the chart&apos;s default would be <span className="font-mono">{pin.chartDefault.tag ?? pin.chartDefault.ref}</span>.
                  </>
                ) : (
                  "; the chart has no default for it."
                )}
                <span className={`ml-1.5 ${mutedClass}`}>
                  (values: <span className="font-mono">{pin.valuesPath.join(".")}</span>)
                </span>
              </p>
            ))}
          </div>
          {row.pins.some((p) => p.diff) && (
            <div className="mt-2">
              <ImageTable
                rows={row.pins.flatMap(({ pin, diff }) =>
                  diff
                    ? [{ key: pin.key, kind: pin.kind, name: pin.name, from: null, to: pin.chartDefault, d: diff, pinnedTag: pin.pinnedTag }]
                    : [],
                )}
              />
            </div>
          )}
        </>
      )}
    </section>
  );
}

interface ImageRow {
  key: string;
  kind: string;
  name: string;
  from: ChartImage | null;
  to: ChartImage | null;
  d: ChartChangeDiff;
  /** Set for a pinned image: the tag the values pin, shown as "from". */
  pinnedTag?: string;
}

function ImageTable({ rows }: { rows: ImageRow[] }) {
  return (
    <Table>
      <thead>
        <tr>
          <th>Object</th>
          <th>From → to</th>
          <th>Digest</th>
          <th className="text-right">Crit</th>
          <th className="text-right">High</th>
          <th className="text-right">Med</th>
          <th className="text-right" title="Known exploited: in CISA's KEV catalog">
            KEV
          </th>
          <th>Scan</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.key}>
            <td>
              <span className={mutedClass}>{r.kind}/</span>
              {r.name}
              <div className={`font-mono text-[11px] ${mutedClass}`}>{fieldOf(r.key)}</div>
            </td>
            <td className="font-mono text-xs">
              <Refs from={r.from} to={r.to} pinnedTag={r.pinnedTag} imageId={r.d.imageId} />
            </td>
            <td>{r.to?.digest ? <ShortDigest digest={r.to.digest} /> : <span className={`text-xs ${mutedClass}`}>—</span>}</td>
            {(["critical", "high", "medium", "exploited"] as const).map((k) => (
              <td key={k} className="whitespace-nowrap text-right">
                <Count k={k} running={r.d.running} candidate={r.d.candidate} />
              </td>
            ))}
            <td>
              <ScanCell d={r.d} />
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/** "repo:1.0 → repo:1.1", or "repo:1.0 → 1.1" when the repository stays the same. */
function Refs({ from, to, pinnedTag, imageId }: { from: ChartImage | null; to: ChartImage | null; pinnedTag?: string; imageId: number | null }) {
  const repo = (i: ChartImage) => `${i.registry}/${i.repository}`;
  const name = (i: ChartImage) => (imageId != null ? <Link href={`/images/${imageId}`} className={linkClass}>{i.ref}</Link> : i.ref);
  if (pinnedTag && to) {
    return (
      <span className="break-all">
        {name(to)}
        <div className={`text-[11px] ${mutedClass}`}>pinned at {pinnedTag}</div>
      </span>
    );
  }
  if (!from && to) {
    return (
      <span className="break-all">
        {name(to)} <span className="font-sans text-[11px] text-blue-700 dark:text-blue-400">new</span>
      </span>
    );
  }
  if (from && !to) {
    return (
      <span className="break-all">
        <span className="line-through">{from.ref}</span> <span className={`font-sans text-[11px] ${mutedClass}`}>dropped</span>
      </span>
    );
  }
  if (!from || !to) return null;
  const sameRepo = repo(from) === repo(to);
  return (
    <span className="break-all">
      <span className={mutedClass}>{sameRepo ? (from.tag ?? from.ref) : from.ref}</span> →{" "}
      {sameRepo ? (
        <>
          {imageId != null ? (
            <Link href={`/images/${imageId}`} className={linkClass}>
              {to.tag ?? to.ref}
            </Link>
          ) : (
            (to.tag ?? to.ref)
          )}
          <div className={`text-[11px] ${mutedClass}`}>{repo(to)}</div>
        </>
      ) : (
        name(to)
      )}
    </span>
  );
}

function Count({ k, running, candidate }: { k: keyof CveCounts; running: CveCounts | null; candidate: CveCounts | null }) {
  const show = (n: number) => (k === "exploited" ? <Exploited n={n} /> : <SeverityCount severity={k.toUpperCase()} n={n} />);
  return (
    <>
      {candidate ? (
        <>
          {show(candidate[k])}
          {running && <Delta n={candidate[k] - running[k]} />}
        </>
      ) : (
        <span className={`text-xs ${mutedClass}`}>—</span>
      )}
      {running && (
        <div className={`text-[11px] tabular-nums ${mutedClass}`} title="The running image">
          now {running[k]}
        </div>
      )}
    </>
  );
}

function ScanCell({ d }: { d: ChartChangeDiff }) {
  if (!d.change.to) return null;
  if (!d.change.to.digest) return <span className={`text-xs ${mutedClass}`} title="The registry did not return a digest for this tag">no digest</span>;
  if (!d.scan) return <span className={`text-xs ${mutedClass}`}>not scanned</span>;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {d.diff && d.scan.status === "done" ? (
        <Link href={`/scans/${d.scan.id}`} className={`text-xs ${linkClass}`}>
          {diffSummary(d.diff)}
        </Link>
      ) : (
        <Link href={`/scans/${d.scan.id}`}>
          <ScanStatusBadge status={d.scan.status} />
        </Link>
      )}
      {d.scan.status === "done" && !d.diff && <span className={`text-xs ${mutedClass}`}>nothing running to compare</span>}
      {d.scan.status === "failed" && d.scan.error && <ErrorText>{d.scan.error}</ErrorText>}
    </div>
  );
}
