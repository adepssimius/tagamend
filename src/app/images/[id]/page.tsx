import Link from "next/link";
import { notFound } from "next/navigation";
import { requireUser } from "@/auth";
import { PrLink } from "@/components/pr-link";
import { SubmitButton } from "@/components/submit-button";
import {
  Ago,
  CveLink,
  Cvss,
  Empty,
  ErrorText,
  ImageName,
  linkClass,
  mutedClass,
  ScanStatusBadge,
  Section,
  SeverityBadge,
  SeverityCount,
  ShortDigest,
  Table,
} from "@/components/ui";
import { getConfig } from "@/lib/config";
import { refreshPrStates } from "@/lib/gitops/pr-state";
import { getDb } from "@/lib/db";
import type { PullRequest } from "@/lib/db/schema";
import { getImagePage } from "@/lib/queries/image";
import { kevFor } from "@/lib/queries/kev";
import { checkTagsNow, openPullRequest, scanRunningBuild, scanTag } from "./actions";

export const dynamic = "force-dynamic";

export default async function ImagePage({ params }: { params: Promise<{ id: string }> }) {
  await requireUser();
  const { id } = await params;
  const imageId = Number(id);
  if (!Number.isInteger(imageId)) notFound();
  const db = await getDb();
  const config = getConfig();
  // On demand: an open PR's state is read from GitHub as the page loads.
  await refreshPrStates(db, { repo: config.GITOPS_REPO, token: config.GITHUB_READ_TOKEN, imageId });
  const page = await getImagePage(db, imageId);
  const prsEnabled = !!getConfig().GITOPS_REPO;
  if (!page) notFound();
  const { image, workloads, runningDigests, vulns, cveCount, tags, pinnedByDigest, runningCounts, staleBuilds, recentScans } = page;
  const kev = await kevFor(db, vulns.map((v) => v.vuln_id));
  const exploited = new Set(vulns.map((v) => v.vuln_id).filter((id) => kev.has(id))).size;
  // Known-exploited first; the query's severity order holds within each group.
  const sortedVulns = [...vulns].sort((a, b) => Number(kev.has(b.vuln_id)) - Number(kev.has(a.vuln_id)));
  const liveWorkloads = workloads.filter((w) => !w.gone_at);
  const runningTags = [...new Set(liveWorkloads.map((w) => w.tag ?? "(digest)"))].sort();
  const candidates = tags.filter((t) => t.is_candidate);
  const others = tags.filter((t) => !t.is_candidate);
  const manyDigests = runningDigests.length > 1;

  return (
    <div>
      <h1 className="break-all text-lg">
        <ImageName registry={image.registry} repository={image.repository} />
      </h1>
      <dl className="mt-3 grid grid-cols-2 gap-px overflow-hidden rounded border border-zinc-200 bg-zinc-200 text-sm sm:grid-cols-6 dark:border-zinc-800 dark:bg-zinc-800">
        {(
          [
            ["Running", <span key="t" className="font-mono text-base">{runningTags.join(", ") || "—"}</span>],
            ["Workloads", liveWorkloads.length],
            ["Critical", <SeverityCount key="c" severity="CRITICAL" n={runningCounts.critical} />],
            ["High", <SeverityCount key="h" severity="HIGH" n={runningCounts.high} />],
            ["Medium", <SeverityCount key="m" severity="MEDIUM" n={runningCounts.medium} />],
            [
              "Known exploited",
              <span key="k" className={exploited ? "text-red-700 dark:text-red-400" : "text-zinc-300 dark:text-zinc-700"} title="CVEs in CISA's Known Exploited Vulnerabilities catalog">
                {exploited}
              </span>,
            ],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="min-w-0 bg-white px-3 py-2 dark:bg-zinc-950">
            <dt className={`text-xs ${mutedClass}`}>{label}</dt>
            <dd className="truncate text-lg font-semibold tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      <p className={`mt-1 text-xs ${mutedClass}`}>
        Each CVE counts once, at its worst severity across the running digests. Candidates below are counted the same way.
      </p>

      {staleBuilds.map((b) => (
        <div
          key={b.podDigest}
          className="mt-3 rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs dark:border-amber-800 dark:bg-amber-950/40"
        >
          <p className="font-medium text-amber-900 dark:text-amber-200">
            {b.workloads.join(", ")} {b.workloads.length === 1 ? "runs" : "run"} an older build of{" "}
            <span className="font-mono">{b.tag ?? "this image"}</span>: <ShortDigest digest={b.podDigest} />.
          </p>
          {b.scanned ? (
            <div className="mt-1 text-amber-900/80 dark:text-amber-200/80">
              <p>The CVEs below are for that build. To update it:</p>
              <ol className="mt-0.5 list-decimal pl-5">
                <li>
                  In Candidate tags, find <span className="font-mono">{b.tag}</span>
                  {b.reportDigest && (
                    <>
                      {" "}
                      at <ShortDigest digest={b.reportDigest} />
                    </>
                  )}
                  , what the tag points to now. Click Scan to see the diff.
                </li>
                <li>Click Open PR. The PR pins the tag to that digest.</li>
                <li>Merge it. Flux rolls the workload, and the node pulls the pinned build.</li>
              </ol>
              <p className="mt-0.5">
                A restart alone does not update it: a node with the tag cached reuses the old build unless the pod pulls
                Always.
              </p>
            </div>
          ) : (
            <div className="mt-1 flex flex-wrap items-center gap-2 text-amber-900/80 dark:text-amber-200/80">
              <p>
                The CVEs below are for what <span className="font-mono">{b.tag}</span> points to now
                {b.reportDigest && (
                  <>
                    {" "}
                    (<ShortDigest digest={b.reportDigest} />)
                  </>
                )}
                , not for what runs. trivy-operator scans the tag, not the pod&apos;s build.
              </p>
              {b.scan && b.scan.status !== "failed" ? (
                <Link href={`/scans/${b.scan.id}`}>
                  <ScanStatusBadge status={b.scan.status} />
                </Link>
              ) : (
                <form action={scanRunningBuild}>
                  <input type="hidden" name="imageId" value={image.id} />
                  <input type="hidden" name="digest" value={b.podDigest} />
                  <SubmitButton pendingText="Queuing…">Scan the running build</SubmitButton>
                </form>
              )}
            </div>
          )}
        </div>
      ))}

      {image.tag_sync_error && (
        <div className="mt-2 rounded border border-red-200 bg-red-50 px-3 py-2 dark:border-red-900 dark:bg-red-950/40">
          <p className="text-xs font-medium text-red-800 dark:text-red-300">Tag sync failed</p>
          <ErrorText>{image.tag_sync_error}</ErrorText>
        </div>
      )}

      <Section title="Workloads" count={workloads.filter((w) => !w.gone_at).length}>
        {workloads.length === 0 ? (
          <Empty>No workloads run this image.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Namespace</th>
                <th>Workload</th>
                <th>Container</th>
                <th>Tag</th>
                <th title="The image digest this workload's pods actually run">Build</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {workloads.map((w) => (
                <tr key={w.id} className={w.gone_at ? "opacity-50" : undefined}>
                  <td>{w.namespace}</td>
                  <td>
                    <span className={mutedClass}>{w.kind}/</span>
                    {w.name}
                  </td>
                  <td>{w.container}</td>
                  <td className="font-mono text-xs">{w.tag ?? <span className={mutedClass}>pinned by digest</span>}</td>
                  <td className="whitespace-nowrap">
                    {w.pod_digest ? (
                      <>
                        <ShortDigest digest={w.pod_digest} />
                        <span
                          className="ml-1.5 text-xs text-amber-700 dark:text-amber-300"
                          title={`The tag now points to ${w.report_digest ?? "another digest"}; this workload has not pulled it`}
                        >
                          behind the tag
                        </span>
                      </>
                    ) : w.report_digest ? (
                      <ShortDigest digest={w.report_digest} />
                    ) : (
                      <span className={mutedClass}>—</span>
                    )}
                  </td>
                  <td>
                    <Ago iso={w.last_seen_at} />
                    {w.gone_at && <span className={`ml-1.5 text-xs ${mutedClass}`}>gone</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section
        title="Candidate tags"
        count={candidates.length}
        note={
          <>
            Tag sync: {image.last_tag_sync_at ? <Ago iso={image.last_tag_sync_at} /> : "due, within a minute"}
            {image.last_tag_sync_at && (
              <form action={checkTagsNow} className="ml-2 inline">
                <input type="hidden" name="imageId" value={image.id} />
                <button type="submit" className={`${linkClass} text-xs`}>
                  check now
                </button>
              </form>
            )}
            {pinnedByDigest && " · Running by digest only, so there are no tags to compare."}
          </>
        }
      >
        {candidates.length === 0 ? (
          <Empty>
            {pinnedByDigest
              ? "Pinned by digest: no candidates."
              : image.tag_sync_error
                ? "The last tag check failed, so there may be newer tags."
                : image.last_tag_sync_at
                  ? "No newer tags found."
                  : "Not checked yet. Tag discovery checks a few images each minute."}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Tag</th>
                <th>Why</th>
                <th>Digest</th>
                <th>First seen</th>
                <th className="text-right">Crit</th>
                <th className="text-right">High</th>
                <th className="text-right">Med</th>
                <th>Scan</th>
                {prsEnabled && <th>PR</th>}
              </tr>
            </thead>
            <tbody>
              <tr className="bg-zinc-50 dark:bg-zinc-900/50">
                <td className="font-mono text-xs">{runningTags.join(", ")}</td>
                <td className={`text-xs ${mutedClass}`}>running now</td>
                <td>{runningDigests.length === 1 ? <ShortDigest digest={runningDigests[0]!.digest} /> : <span className={`text-xs ${mutedClass}`}>{runningDigests.length} digests</span>}</td>
                <td />
                <td className="text-right">
                  <SeverityCount severity="CRITICAL" n={runningCounts.critical} />
                </td>
                <td className="text-right">
                  <SeverityCount severity="HIGH" n={runningCounts.high} />
                </td>
                <td className="text-right">
                  <SeverityCount severity="MEDIUM" n={runningCounts.medium} />
                </td>
                <td />
                {prsEnabled && <td />}
              </tr>
              {candidates.map((t) => (
                <tr key={t.id}>
                  <td className="font-mono text-xs">{t.tag}</td>
                  <td className={`text-xs ${mutedClass}`}>{t.reason ?? "—"}</td>
                  <td>{t.digest ? <ShortDigest digest={t.digest} /> : <span className={mutedClass}>—</span>}</td>
                  <td>
                    <Ago iso={t.first_seen_at} />
                  </td>
                  {(["critical", "high", "medium"] as const).map((k) => (
                    <td key={k} className="whitespace-nowrap text-right">
                      {t.counts ? (
                        <>
                          <SeverityCount severity={k.toUpperCase()} n={t.counts[k]} />
                          <Delta n={t.counts[k] - runningCounts[k]} />
                        </>
                      ) : (
                        <span className={`text-xs ${mutedClass}`}>—</span>
                      )}
                    </td>
                  ))}
                  <td>
                    <div className="flex flex-wrap items-center gap-2">
                      {t.scan && (t.scan.status !== "done" || !t.diff) && (
                        <Link href={`/scans/${t.scan.id}`}>
                          <ScanStatusBadge status={t.scan.status} />
                        </Link>
                      )}
                      {t.diff && t.scan && (
                        <Link href={`/scans/${t.scan.id}`} className={`text-xs ${linkClass}`}>
                          {t.diff.summary}
                        </Link>
                      )}
                      {t.digest && (!t.scan || t.scan.status === "failed") ? (
                        <form action={scanTag}>
                          <input type="hidden" name="tagId" value={t.id} />
                          <SubmitButton pendingText="Queuing…">{t.scan ? "Retry" : "Scan"}</SubmitButton>
                        </form>
                      ) : null}
                      {!t.digest && <span className={`text-xs ${mutedClass}`}>no digest</span>}
                    </div>
                    {t.scan?.status === "failed" && t.scan.error && <ErrorText>{t.scan.error}</ErrorText>}
                  </td>
                  {prsEnabled && (
                    <td>
                      <PrCell prs={t.prs} scanId={t.scan?.status === "done" ? t.scan.id : null} workloads={liveWorkloads} />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {others.length > 0 && (
          <details className="mt-2 text-xs">
            <summary className={`cursor-pointer ${mutedClass}`}>{others.length} {others.length === 1 ? "tag" : "tags"} not a candidate</summary>
            <ul className="mt-1 space-y-0.5">
              {others.map((t) => (
                <li key={t.id}>
                  <span className="font-mono">{t.tag}</span>
                  {t.reason && <span className={`ml-2 ${mutedClass}`}>{t.reason}</span>}
                </li>
              ))}
            </ul>
          </details>
        )}
      </Section>

      <Section
        title="CVEs"
        count={cveCount}
        note={
          manyDigests ? (
            <>
              This image runs {runningDigests.length} digests; the list is their union.{" "}
              {runningDigests.map((d, i) => (
                <span key={d.id}>
                  {i > 0 && ", "}
                  <ShortDigest digest={d.digest} />
                </span>
              ))}
            </>
          ) : runningDigests[0] ? (
            <>
              Digest <ShortDigest digest={runningDigests[0].digest} />
              {runningDigests[0].os_family && ` · ${runningDigests[0].os_family} ${runningDigests[0].os_name ?? ""}`} · scanned{" "}
              <Ago iso={runningDigests[0].scanned_at} />
              {runningDigests[0].scanner_version && ` · Trivy ${runningDigests[0].scanner_version}`}
            </>
          ) : undefined
        }
      >
        {vulns.length === 0 ? (
          <Empty>
            {runningDigests.length === 0 ? "No vulnerability report for a running digest yet." : "No findings at the configured severities."}
          </Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Severity</th>
                <th className="text-right">CVSS</th>
                <th>ID</th>
                <th>Package</th>
                <th>Installed</th>
                <th>Fixed in</th>
                <th>Title</th>
                {manyDigests && <th>Digests</th>}
              </tr>
            </thead>
            <tbody>
              {sortedVulns.map((v) => (
                <tr key={v.id}>
                  <td>
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td className="text-right">
                    <Cvss score={v.score} />
                  </td>
                  <td>
                    <CveLink id={v.vuln_id} link={v.link} kev={kev.get(v.vuln_id)} />
                  </td>
                  <td className="font-mono text-xs">{v.package}</td>
                  <td className="font-mono text-xs">{v.installed_version}</td>
                  <td className="font-mono text-xs">{v.fixed_version ?? <span className={mutedClass}>—</span>}</td>
                  <td className="max-w-md text-xs">{v.title}</td>
                  {manyDigests && (
                    <td className="tabular-nums text-xs">
                      {v.digestIds.length}/{runningDigests.length}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      {recentScans.length > 0 && (
        <Section title="Scans" count={recentScans.length}>
          <Table>
            <thead>
              <tr>
                <th>Tag</th>
                <th>Status</th>
                <th>Requested</th>
                <th>By</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((s) => (
                <tr key={s.id}>
                  <td className="font-mono text-xs">
                    <Link href={`/scans/${s.id}`} className={linkClass}>
                      {s.tag}
                    </Link>
                  </td>
                  <td>
                    <ScanStatusBadge status={s.status} />
                  </td>
                  <td>
                    <Ago iso={s.requested_at} />
                  </td>
                  <td className="text-xs">{s.requested_by ?? "—"}</td>
                  <td className="text-xs">{s.diff?.summary ?? s.error ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Section>
      )}
    </div>
  );
}

/** A workload's key in a PR request: "namespace/Kind/name". */
const workloadKey = (w: { namespace: string; kind: string; name: string }) => `${w.namespace}/${w.kind}/${w.name}`;

/** One PR request: its link and state, its progress, or its failure. */
function PrState({ pr }: { pr: PullRequest }) {
  const only = pr.workloads ? (JSON.parse(pr.workloads) as string[]).map((k) => k.split("/").pop()).join(", ") : null;
  const scope = only ? <span className={`ml-1 text-xs ${mutedClass}`}>({only})</span> : null;
  if (pr.status === "opened" && pr.pr_url && pr.pr_number != null) {
    return (
      <div>
        <PrLink number={pr.pr_number} url={pr.pr_url} state={pr.pr_state} />
        {scope}
      </div>
    );
  }
  if (pr.status === "queued" || pr.status === "running") {
    return (
      <div className={`text-xs ${mutedClass}`}>
        {pr.status === "queued" ? "queued" : "opening…"}
        {scope}
      </div>
    );
  }
  return pr.error ? <ErrorText>{pr.error}</ErrorText> : null;
}

/**
 * The PR requests for one candidate, and the button that requests another once
 * it is scanned. With more than one workload on the image, the button offers a
 * choice of which to move, so one instance can try a version before the rest.
 */
function PrCell({
  prs,
  scanId,
  workloads,
}: {
  prs: PullRequest[];
  scanId: number | null;
  workloads: { namespace: string; kind: string; name: string }[];
}) {
  const allOpen = prs.some(
    (p) => p.workloads == null && p.status !== "failed" && (p.pr_state == null || p.pr_state === "open" || p.pr_state === "draft"),
  );
  const unique = [...new Map(workloads.map((w) => [workloadKey(w), w])).values()];
  return (
    <div className="space-y-1">
      {prs.map((p) => (
        <PrState key={p.id} pr={p} />
      ))}
      {!scanId ? (
        prs.length === 0 && (
          <span className={`text-xs ${mutedClass}`} title="Scan the candidate first; the PR carries its diff">
            scan first
          </span>
        )
      ) : allOpen || unique.length === 0 ? null : (
        <form action={openPullRequest} className="space-y-1">
          <input type="hidden" name="scanId" value={scanId} />
          {unique.length > 1 && (
            <details className="text-xs">
              <summary className={`cursor-pointer ${mutedClass}`}>for all {unique.length} workloads</summary>
              <div className="mt-1 space-y-0.5">
                {unique.map((w) => (
                  <label key={workloadKey(w)} className="flex items-center gap-1.5 whitespace-nowrap">
                    <input type="hidden" name="allWorkloads" value={workloadKey(w)} />
                    <input type="checkbox" name="workload" value={workloadKey(w)} defaultChecked />
                    {w.namespace}/{w.name}
                  </label>
                ))}
              </div>
            </details>
          )}
          <SubmitButton pendingText="Queuing…">{prs.some((p) => p.status === "failed") ? "Retry PR" : "Open PR"}</SubmitButton>
        </form>
      )}
    </div>
  );
}

/** The change against the running image: fewer is green, more is red. */
function Delta({ n }: { n: number }) {
  if (n === 0) return null;
  return (
    <span className={`ml-1 text-xs tabular-nums ${n < 0 ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"}`}>
      {n < 0 ? `−${-n}` : `+${n}`}
    </span>
  );
}
