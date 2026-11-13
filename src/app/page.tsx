import Link from "next/link";
import { requireUser } from "@/auth";
import { ExposureBadge } from "@/components/exposure";
import { Ago, Empty, ImageName, linkClass, mutedClass, ScanStatusBadge, SeverityCount, Table } from "@/components/ui";
import { getDb } from "@/lib/db";
import { chartsWithCandidate } from "@/lib/queries/charts";
import { getOverview, type MinSeverity, type OverviewOptions, type OverviewRow, SORT_KEYS, type SortKey } from "@/lib/queries/overview";

export const dynamic = "force-dynamic";

type SP = Record<string, string | string[] | undefined>;
const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) || undefined;

function parseOptions(sp: SP): OverviewOptions {
  const sev = one(sp.severity)?.toUpperCase();
  const sort = one(sp.sort);
  const dir = one(sp.dir);
  return {
    namespace: one(sp.namespace),
    minSeverity: sev === "CRITICAL" || sev === "HIGH" || sev === "MEDIUM" ? (sev as MinSeverity) : undefined,
    // "candidate=1" is the old single checkbox; keep links to it working.
    needs: [
      ...(one(sp.candidate) === "1" ? (["candidate"] as const) : []),
      ...(one(sp.stale) === "1" ? (["stale"] as const) : []),
    ],
    exploited: one(sp.kev) === "1",
    exposure: one(sp.exposure) === "internet" || one(sp.exposure) === "internet-app" ? (one(sp.exposure) as "internet" | "internet-app") : undefined,
    sort: SORT_KEYS.includes(sort as SortKey) ? (sort as SortKey) : undefined,
    dir: dir === "asc" || dir === "desc" ? dir : undefined,
  };
}

export default async function OverviewPage({ searchParams }: { searchParams: Promise<SP> }) {
  await requireUser();
  const sp = await searchParams;
  const opts = parseOptions(sp);
  const db = await getDb();
  const [{ rows, totals, namespaces, lastReportSync }, chartUpdates] = await Promise.all([getOverview(db, opts), chartsWithCandidate(db)]);

  // Sort links keep the filters and flip direction when the column is already active.
  const sortHref = (key: SortKey) => {
    const p = new URLSearchParams();
    if (opts.namespace) p.set("namespace", opts.namespace);
    if (opts.minSeverity) p.set("severity", opts.minSeverity);
    if (opts.needs?.includes("candidate")) p.set("candidate", "1");
    if (opts.needs?.includes("stale")) p.set("stale", "1");
    if (opts.exploited) p.set("kev", "1");
    if (opts.exposure) p.set("exposure", opts.exposure);
    p.set("sort", key);
    const defaultDir = key === "image" ? "asc" : "desc";
    const current = opts.sort === key ? (opts.dir ?? defaultDir) : undefined;
    p.set("dir", current ? (current === "asc" ? "desc" : "asc") : defaultDir);
    return `/?${p}`;
  };
  const SortTh = ({ k, children, className }: { k: SortKey; children: React.ReactNode; className?: string }) => {
    const active = opts.sort === k;
    const dir = active ? (opts.dir ?? (k === "image" ? "asc" : "desc")) : null;
    return (
      <th className={className}>
        <Link href={sortHref(k)} className={active ? "text-zinc-900 dark:text-zinc-100" : "hover:text-zinc-900 dark:hover:text-zinc-100"}>
          {children}
          {dir && <span className="ml-0.5">{dir === "asc" ? "▲" : "▼"}</span>}
        </Link>
      </th>
    );
  };
  const filtered = !!(opts.namespace || opts.minSeverity || opts.needs?.length || opts.exploited || opts.exposure);

  return (
    <div>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-lg font-semibold">Images in use</h1>
        <p className={`text-xs ${mutedClass}`}>
          {chartUpdates > 0 && (
            <>
              <Link href="/charts" className={linkClass}>
                {chartUpdates} {chartUpdates === 1 ? "chart has" : "charts have"} a newer version
              </Link>{" "}
              ·{" "}
            </>
          )}
          Tags checked: {totals.tagsChecked} of {totals.images} images ·{" "}
          Last report sync: <Ago iso={lastReportSync?.finished_at} />
          {lastReportSync?.ok === 0 && (
            <Link href="/status" className="ml-1 text-red-700 hover:underline dark:text-red-400">
              (failed)
            </Link>
          )}
        </p>
      </div>

      <dl className="mt-3 grid grid-cols-3 gap-px overflow-hidden rounded border border-zinc-200 bg-zinc-200 text-sm sm:grid-cols-8 dark:border-zinc-800 dark:bg-zinc-800">
        {(
          [
            ["Images", totals.images],
            ["Workloads", totals.workloads],
            ["Critical", <SeverityCount key="c" severity="CRITICAL" n={totals.critical} />],
            ["High", <SeverityCount key="h" severity="HIGH" n={totals.high} />],
            ["Medium", <SeverityCount key="m" severity="MEDIUM" n={totals.medium} />],
            ["Known exploited", <Exploited key="k" n={totals.exploited} />],
            ["With a candidate", totals.withCandidate],
            ["Candidate scanned", totals.candidatesScanned],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="bg-white px-3 py-2 dark:bg-zinc-950">
            <dt className={`text-xs ${mutedClass}`}>{label}</dt>
            <dd className="text-lg font-semibold tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      <p className={`mt-1 text-xs ${mutedClass}`}>
        CVE counts are per image: each CVE counts once per image, at the worst severity any running digest gives it, and
        totals add up the images{filtered ? " shown" : ""}.
      </p>

      <form method="get" className="mt-4 flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-0.5">
          <span className={`text-xs ${mutedClass}`}>Namespace</span>
          <select name="namespace" defaultValue={opts.namespace ?? ""} className={inputClass}>
            <option value="">All</option>
            {namespaces.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-0.5">
          <span className={`text-xs ${mutedClass}`}>At least</span>
          <select name="severity" defaultValue={opts.minSeverity ?? ""} className={inputClass}>
            <option value="">Any</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>
        </label>
        <label className="flex flex-col gap-0.5">
          <span className={`text-xs ${mutedClass}`}>Exposure</span>
          <select name="exposure" defaultValue={opts.exposure ?? ""} className={inputClass}>
            <option value="">Any</option>
            <option value="internet">Internet</option>
            <option value="internet-app">Internet, app login only</option>
          </select>
        </label>
        <fieldset className="flex flex-col gap-0.5">
          <legend className={`text-xs ${mutedClass}`}>Needs action (any)</legend>
          <div className="flex items-center gap-3 pb-1">
            <label className="flex items-center gap-1.5">
              <input type="checkbox" name="candidate" value="1" defaultChecked={opts.needs?.includes("candidate")} />
              Has a candidate
            </label>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" name="stale" value="1" defaultChecked={opts.needs?.includes("stale")} />
              Older build running
            </label>
          </div>
        </fieldset>
        <fieldset className="flex flex-col gap-0.5">
          <legend className={`text-xs ${mutedClass}`}>And</legend>
          <label className="flex items-center gap-1.5 pb-1">
            <input type="checkbox" name="kev" value="1" defaultChecked={opts.exploited} />
            Known exploited
          </label>
        </fieldset>
        {opts.sort && <input type="hidden" name="sort" value={opts.sort} />}
        {opts.dir && <input type="hidden" name="dir" value={opts.dir} />}
        <button type="submit" className={`${inputClass} font-medium hover:bg-zinc-100 dark:hover:bg-zinc-800`}>
          Apply
        </button>
        {filtered && (
          <Link href="/" className={`pb-1 text-xs ${linkClass}`}>
            Clear filters
          </Link>
        )}
      </form>

      <div className="mt-3">
        {rows.length === 0 ? (
          <Empty>{filtered ? "No images match these filters." : "No running images yet. The report sync fills this in."}</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <SortTh k="image">Image</SortTh>
                <th>Running tag</th>
                <SortTh k="workloads" className="text-right">
                  Workloads
                </SortTh>
                <SortTh k="critical" className="text-right">
                  Crit
                </SortTh>
                <SortTh k="high" className="text-right">
                  High
                </SortTh>
                <SortTh k="medium" className="text-right">
                  Med
                </SortTh>
                <SortTh k="exploited" className="text-right">
                  <span title="CVEs in CISA's Known Exploited Vulnerabilities catalog">KEV</span>
                </SortTh>
                <SortTh k="exposure">Exposure</SortTh>
                <SortTh k="candidate">Best candidate</SortTh>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.imageId}>
                  <td>
                    <Link href={`/images/${r.imageId}`} className="hover:underline">
                      <ImageName registry={r.registry} repository={r.repository} />
                    </Link>
                    {r.digests > 1 && (
                      <span className={`ml-1.5 text-xs ${mutedClass}`} title="Counts are the union of these digests">
                        {r.digests} digests
                      </span>
                    )}
                  </td>
                  <td className="font-mono text-xs">
                    {r.tags.map((t) => (
                      <div key={t ?? "@"}>{t ?? <span className={mutedClass}>pinned by digest</span>}</div>
                    ))}
                    {r.staleBuild && (
                      <div className="text-xs text-amber-700 dark:text-amber-300" title="A pod runs an older build than this tag points to now">
                        older build running
                      </div>
                    )}
                  </td>
                  <td className="text-right tabular-nums" title={r.namespaces.join(", ")}>
                    {r.workloads}
                  </td>
                  <td className="text-right">
                    <SeverityCount severity="CRITICAL" n={r.critical} />
                  </td>
                  <td className="text-right">
                    <SeverityCount severity="HIGH" n={r.high} />
                  </td>
                  <td className="text-right">
                    <SeverityCount severity="MEDIUM" n={r.medium} />
                  </td>
                  <td className="text-right">
                    <Exploited n={r.exploited} />
                  </td>
                  <td>
                    <ExposureBadge exposure={r.exposure} />
                  </td>
                  <td>
                    {r.candidate ? (
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <span className="font-mono text-xs" title={r.candidate.reason ?? undefined}>
                          {r.candidate.tag}
                        </span>
                        {r.candidateCount > 1 && <span className={`text-xs ${mutedClass}`}>+{r.candidateCount - 1}</span>}
                        {r.candidate.scan ? (
                          r.candidate.scan.diff ? (
                            <Link href={`/scans/${r.candidate.scan.id}`} className={`text-xs ${linkClass}`}>
                              {r.candidate.scan.diff.summary}
                            </Link>
                          ) : (
                            <Link href={`/scans/${r.candidate.scan.id}`}>
                              <ScanStatusBadge status={r.candidate.scan.status} />
                            </Link>
                          )
                        ) : (
                          <span className={`text-xs ${mutedClass}`}>not scanned</span>
                        )}
                      </div>
                    ) : (
                      <NoCandidate imageId={r.imageId} check={r.tagCheck} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </div>
    </div>
  );
}

const inputClass =
  "rounded border border-zinc-300 bg-white px-2 py-1 text-sm dark:border-zinc-700 dark:bg-zinc-900";

/** Why a row has no candidate: not checked yet, failed, pinned, or checked and current. */
function NoCandidate({ imageId, check }: { imageId: number; check: OverviewRow["tagCheck"] }) {
  if (check.pinned) return <span className={`text-xs ${mutedClass}`}>pinned by digest</span>;
  if (check.error) {
    return (
      <Link href={`/images/${imageId}`} className="text-xs text-red-700 hover:underline dark:text-red-400" title={check.error}>
        check failed
      </Link>
    );
  }
  if (!check.checkedAt) return <span className={`text-xs ${mutedClass}`}>not checked yet</span>;
  return (
    <span className={`text-xs ${mutedClass}`}>
      {check.floating ? "no new digest" : "up to date"} · <Ago iso={check.checkedAt} />
    </span>
  );
}

/** Count of known-exploited CVEs: red when any. */
function Exploited({ n }: { n: number }) {
  return n > 0 ? (
    <span className="font-semibold tabular-nums text-red-700 dark:text-red-400">{n}</span>
  ) : (
    <span className="tabular-nums text-zinc-300 dark:text-zinc-700">0</span>
  );
}
