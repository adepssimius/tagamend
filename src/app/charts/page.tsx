import Link from "next/link";
import { requireUser } from "@/auth";
import { ChartPrState, ChartScanState, Exploited, SourceName } from "./components";
import { Ago, Empty, mutedClass, SeverityCount, Table } from "@/components/ui";
import { getDb } from "@/lib/db";
import { getConfig } from "@/lib/config";
import { getChartList } from "@/lib/queries/charts";
import { refreshChartPrStates } from "@/lib/gitops/pr-state";

export const dynamic = "force-dynamic";

export default async function ChartsPage() {
  await requireUser();
  const db = await getDb();
  const config = getConfig();
  await refreshChartPrStates(db, { repo: config.GITOPS_REPO, token: config.GITHUB_READ_TOKEN });
  const rows = await getChartList(db);
  const withCandidate = rows.filter((r) => r.best).length;
  const failing = rows.filter((r) => r.chart.sync_error).length;

  return (
    <div>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-lg font-semibold">Helm charts</h1>
        <p className={`text-xs ${mutedClass}`}>
          {rows.length} HelmReleases · {withCandidate} with a newer version
          {failing > 0 && <span className="text-red-700 dark:text-red-400"> · {failing} failed to check</span>}
        </p>
      </div>
      <p className={`mt-1 text-xs ${mutedClass}`}>
        CVE counts are for the images the HelmRelease runs now, counted per image and added up. HelmReleases with a newer
        version come first.
      </p>

      <div className="mt-3">
        {rows.length === 0 ? (
          <Empty>No HelmReleases yet. The chart check fills this in.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>HelmRelease</th>
                <th>Chart</th>
                <th title="spec.chart.spec.version as written, and what Flux installed">Version</th>
                <th>Source</th>
                <th className="text-right">Crit</th>
                <th className="text-right">High</th>
                <th className="text-right">Med</th>
                <th className="text-right" title="CVEs in CISA's Known Exploited Vulnerabilities catalog">
                  KEV
                </th>
                <th>Newest candidate</th>
                <th>Scans</th>
                <th>PR</th>
                <th>Last check</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ chart, running, best, candidateCount, pr, workloads }) => (
                <tr key={chart.id}>
                  <td className="whitespace-nowrap">
                    <Link href={`/charts/${chart.id}`} className="hover:underline">
                      <span className={mutedClass}>{chart.namespace}/</span>
                      <span className="font-medium">{chart.name}</span>
                    </Link>
                    {workloads > 0 && (
                      <span className={`ml-1.5 text-xs ${mutedClass}`} title="Live workloads this HelmRelease applies">
                        {workloads}
                      </span>
                    )}
                  </td>
                  <td className="whitespace-nowrap font-mono text-xs">{chart.chart}</td>
                  <td className="whitespace-nowrap font-mono text-xs">
                    <InstalledVersion version={chart.version} installed={chart.installed_version} />
                  </td>
                  <td className="text-xs">
                    <SourceName url={chart.source_url} hostOnly />
                  </td>
                  <td className="text-right">
                    <SeverityCount severity="CRITICAL" n={running.critical} />
                  </td>
                  <td className="text-right">
                    <SeverityCount severity="HIGH" n={running.high} />
                  </td>
                  <td className="text-right">
                    <SeverityCount severity="MEDIUM" n={running.medium} />
                  </td>
                  <td className="text-right">
                    <Exploited n={running.exploited} />
                  </td>
                  <td>
                    {best ? (
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <Link
                          href={`/charts/${chart.id}?candidate=${best.candidate.id}#candidate`}
                          className="font-mono text-xs text-blue-700 hover:underline dark:text-blue-400"
                          title={best.candidate.reason ?? undefined}
                        >
                          {best.candidate.version}
                        </Link>
                        {candidateCount > 1 && <span className={`text-xs ${mutedClass}`}>+{candidateCount - 1}</span>}
                        <span className={`text-xs ${mutedClass}`}>
                          {best.candidate.render_error ? (
                            <span className="text-red-700 dark:text-red-400" title={best.candidate.render_error}>
                              render failed
                            </span>
                          ) : !best.candidate.rendered_at ? (
                            "not rendered yet"
                          ) : best.changed === 0 ? (
                            "same images"
                          ) : (
                            `${best.changed} ${best.changed === 1 ? "image" : "images"} change`
                          )}
                        </span>
                      </div>
                    ) : (
                      <span className={`text-xs ${mutedClass}`}>{chart.last_sync_at ? "up to date" : "not checked yet"}</span>
                    )}
                  </td>
                  <td>{best && <ChartScanState state={best} />}</td>
                  <td>
                    {pr && (
                      <div className="flex items-center gap-1.5">
                        <ChartPrState pr={pr} short />
                        <span className={`font-mono text-xs ${mutedClass}`}>{pr.to_version}</span>
                      </div>
                    )}
                  </td>
                  <td className="text-xs">
                    <Ago iso={chart.last_sync_at} />
                    {chart.sync_error && (
                      <div className="max-w-xs truncate text-red-700 dark:text-red-400" title={chart.sync_error}>
                        {chart.sync_error}
                      </div>
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

/** "1.2.3", or "* → 1.2.3" when the written version is a range. */
function InstalledVersion({ version, installed }: { version: string; installed: string | null }) {
  if (!installed || installed === version) return <>{version}</>;
  return (
    <span title="Written in the HelmRelease → installed by Flux">
      <span className={mutedClass}>{version} →</span> {installed}
    </span>
  );
}
