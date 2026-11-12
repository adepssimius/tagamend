import Link from "next/link";
import { notFound } from "next/navigation";
import { requireUser } from "@/auth";
import { SubmitButton } from "@/components/submit-button";
import {
  Ago,
  CveLink,
  Empty,
  ErrorText,
  ImageName,
  linkClass,
  mutedClass,
  ScanStatusBadge,
  Section,
  SeverityBadge,
  ShortDigest,
  Table,
} from "@/components/ui";
import { getDb } from "@/lib/db";
import { getImagePage } from "@/lib/queries/image";
import { scanTag } from "./actions";

export const dynamic = "force-dynamic";

export default async function ImagePage({ params }: { params: Promise<{ id: string }> }) {
  await requireUser();
  const { id } = await params;
  const imageId = Number(id);
  if (!Number.isInteger(imageId)) notFound();
  const page = await getImagePage(await getDb(), imageId);
  if (!page) notFound();
  const { image, workloads, runningDigests, vulns, cveCount, tags, pinnedByDigest, recentScans } = page;
  const candidates = tags.filter((t) => t.is_candidate);
  const others = tags.filter((t) => !t.is_candidate);
  const manyDigests = runningDigests.length > 1;

  return (
    <div>
      <h1 className="break-all text-lg">
        <ImageName registry={image.registry} repository={image.repository} />
      </h1>
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
            Tag sync: <Ago iso={image.last_tag_sync_at} />
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
                <th>Scan</th>
              </tr>
            </thead>
            <tbody>
              {candidates.map((t) => (
                <tr key={t.id}>
                  <td className="font-mono text-xs">{t.tag}</td>
                  <td className={`text-xs ${mutedClass}`}>{t.reason ?? "—"}</td>
                  <td>{t.digest ? <ShortDigest digest={t.digest} /> : <span className={mutedClass}>—</span>}</td>
                  <td>
                    <Ago iso={t.first_seen_at} />
                  </td>
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
                <th>ID</th>
                <th>Package</th>
                <th>Installed</th>
                <th>Fixed in</th>
                <th>Title</th>
                {manyDigests && <th>Digests</th>}
              </tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr key={v.id}>
                  <td>
                    <SeverityBadge severity={v.severity} />
                  </td>
                  <td>
                    <CveLink id={v.vuln_id} link={v.link} />
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
