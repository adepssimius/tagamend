import Link from "next/link";
import { requireUser } from "@/auth";
import {
  Ago,
  Empty,
  ErrorText,
  ImageName,
  linkClass,
  mutedClass,
  OkBadge,
  ScanStatusBadge,
  Section,
  Table,
} from "@/components/ui";
import { getConfig } from "@/lib/config";
import { getDb } from "@/lib/db";
import type { SyncName } from "@/lib/db/schema";
import { getStatusPage, imageRefTag, LOOPS, sameVersion } from "@/lib/queries/status";

export const dynamic = "force-dynamic";

const LOOP_NAMES: Record<SyncName, string> = {
  report_sync: "Report sync",
  tag_sync: "Tag discovery",
  scan_queue: "Scan queue",
  pr_queue: "PR queue",
};

const warnClass = "font-semibold text-amber-700 dark:text-amber-300";

export default async function StatusPage() {
  await requireUser();
  const page = await getStatusPage(await getDb());
  const trivyImage = getConfig().TRIVY_IMAGE;
  const clientVersion = imageRefTag(trivyImage);
  const differs = (v: string | undefined) => !!clientVersion && v !== undefined && !sameVersion(v, clientVersion);
  const serverDiffers = differs(page.trivyServerVersion?.value);
  const reportDiffers = differs(page.trivyReportVersion?.value);

  return (
    <div>
      <h1 className="text-lg font-semibold">Status</h1>

      <Section title="Background loops">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {LOOPS.map((name) => {
            const runs = page.runs[name];
            const latest = runs[0];
            return (
              <div key={name} className="min-w-0">
                <h3 className="flex items-center gap-2 text-sm font-medium">
                  {LOOP_NAMES[name]}
                  {latest && <OkBadge ok={latest.ok} />}
                  {latest && (
                    <span className={`text-xs font-normal ${mutedClass}`}>
                      <Ago iso={latest.finished_at ?? latest.started_at} />
                    </span>
                  )}
                </h3>
                <div className="mt-1">
                  {runs.length === 0 ? (
                    <Empty>Has not run yet.</Empty>
                  ) : (
                    <Table>
                      <thead>
                        <tr>
                          <th>Started</th>
                          <th>Result</th>
                          <th>Detail</th>
                        </tr>
                      </thead>
                      <tbody>
                        {runs.map((r) => (
                          <tr key={r.id}>
                            <td>
                              <Ago iso={r.started_at} />
                            </td>
                            <td>
                              <OkBadge ok={r.ok} />
                            </td>
                            <td className="font-mono text-[11px] [overflow-wrap:anywhere]">
                              {r.error ? <ErrorText>{r.error}</ErrorText> : <span className={mutedClass}>{r.detail}</span>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Section>

      <Section title="Scan queue" count={page.active.length}>
        {page.active.length === 0 ? (
          <Empty>Nothing queued or running.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Image</th>
                <th>Tag</th>
                <th>Status</th>
                <th>Requested</th>
                <th>By</th>
                <th>Job</th>
              </tr>
            </thead>
            <tbody>
              {page.active.map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link href={`/images/${s.image_id}`} className="hover:underline">
                      <ImageName registry={s.registry} repository={s.repository} />
                    </Link>
                  </td>
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
                  <td className="font-mono text-xs">{s.job_name ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="Pull requests" count={page.pullRequests.length}>
        {page.pullRequests.length === 0 ? (
          <Empty>None requested yet.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Image</th>
                <th>To tag</th>
                <th>Status</th>
                <th>Requested</th>
                <th>By</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {page.pullRequests.map((p) => (
                <tr key={p.id}>
                  <td>
                    <Link href={`/images/${p.image_id}`} className="hover:underline">
                      <ImageName registry={p.registry} repository={p.repository} />
                    </Link>
                  </td>
                  <td className="font-mono text-xs">{p.to_tag}</td>
                  <td className="text-xs">{p.status}</td>
                  <td>
                    <Ago iso={p.requested_at} />
                  </td>
                  <td className="text-xs">{p.requested_by ?? "—"}</td>
                  <td className="text-xs">
                    {p.pr_url ? (
                      <a href={p.pr_url} className={linkClass} target="_blank" rel="noreferrer">
                        PR #{p.pr_number}
                      </a>
                    ) : p.error ? (
                      <ErrorText>{p.error}</ErrorText>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="Recent scan failures" count={page.failed.length}>
        {page.failed.length === 0 ? (
          <Empty>None.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Image</th>
                <th>Tag</th>
                <th>Finished</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {page.failed.map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link href={`/images/${s.image_id}`} className="hover:underline">
                      <ImageName registry={s.registry} repository={s.repository} />
                    </Link>
                  </td>
                  <td className="font-mono text-xs">
                    <Link href={`/scans/${s.id}`} className={linkClass}>
                      {s.tag}
                    </Link>
                  </td>
                  <td>
                    <Ago iso={s.finished_at ?? s.requested_at} />
                  </td>
                  <td className="max-w-xl">
                    <ErrorText>{s.error ?? "—"}</ErrorText>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="Registry errors" count={page.tagSyncErrors.length} note="Images whose last tag listing failed.">
        {page.tagSyncErrors.length === 0 ? (
          <Empty>None.</Empty>
        ) : (
          <Table>
            <thead>
              <tr>
                <th>Image</th>
                <th>Last sync</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {page.tagSyncErrors.map((i) => (
                <tr key={i.id}>
                  <td>
                    <Link href={`/images/${i.id}`} className="hover:underline">
                      <ImageName registry={i.registry} repository={i.repository} />
                    </Link>
                  </td>
                  <td>
                    <Ago iso={i.last_tag_sync_at} />
                  </td>
                  <td className="max-w-xl">
                    <ErrorText>{i.tag_sync_error}</ErrorText>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section title="Trivy versions" note="The scan client (TRIVY_IMAGE) must match the Trivy server, or scans fail.">
        {(serverDiffers || reportDiffers) && (
          <p className="mb-2 rounded border border-amber-300 bg-amber-50 px-3 py-1.5 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
            Version mismatch: <span className="font-mono text-xs">TRIVY_IMAGE</span> is {clientVersion}, but{" "}
            {serverDiffers && <>the Trivy server is {page.trivyServerVersion?.value}</>}
            {serverDiffers && reportDiffers && " and "}
            {reportDiffers && <>the newest report used {page.trivyReportVersion?.value}</>}.
          </p>
        )}
        <Table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Version</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                Scan client <span className={`font-mono text-xs ${mutedClass}`}>{trivyImage}</span>
              </td>
              <td className="font-mono text-xs">{clientVersion ?? "no tag"}</td>
              <td />
            </tr>
            <tr>
              <td>Newest VulnerabilityReport</td>
              <td className={`font-mono text-xs ${reportDiffers ? warnClass : ""}`}>{page.trivyReportVersion?.value ?? "unknown"}</td>
              <td>
                <Ago iso={page.trivyReportVersion?.updated_at} />
              </td>
            </tr>
            <tr>
              <td>Trivy server</td>
              <td className={`font-mono text-xs ${serverDiffers ? warnClass : ""}`}>{page.trivyServerVersion?.value ?? "unknown"}</td>
              <td>
                <Ago iso={page.trivyServerVersion?.updated_at} />
              </td>
            </tr>
          </tbody>
        </Table>
      </Section>
    </div>
  );
}
