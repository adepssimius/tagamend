import Link from "next/link";
import { notFound } from "next/navigation";
import { requireUser } from "@/auth";
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
  ShortDigest,
  Table,
} from "@/components/ui";
import { getDb } from "@/lib/db";
import type { Kev, Vulnerability } from "@/lib/db/schema";
import { kevFor } from "@/lib/queries/kev";
import { getScanPage } from "@/lib/queries/scan";
import { diffSummary } from "@/lib/trivy/diff";

export const dynamic = "force-dynamic";

function VulnTable({ rows, kev }: { rows: Vulnerability[]; kev: Map<string, Kev> }) {
  return (
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
        </tr>
      </thead>
      <tbody>
        {rows.map((v) => (
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
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ running?: string }>;
}) {
  await requireUser();
  const { id } = await params;
  const { running } = await searchParams;
  const scanId = Number(id);
  if (!Number.isInteger(scanId)) notFound();
  const page = await getScanPage(await getDb(), scanId, running ? Number(running) : undefined);
  if (!page) notFound();
  const { scan, image, resultDigest, runningDigests, comparedWith, diff } = page;
  const kev = await kevFor(
    await getDb(),
    diff ? [...diff.fixed, ...diff.introduced, ...diff.stillPresent.map((s) => s.running)].map((v) => v.vuln_id) : [],
  );

  return (
    <div>
      <p className={`text-xs ${mutedClass}`}>
        <Link href={`/images/${image.id}`} className="hover:underline">
          <ImageName registry={image.registry} repository={image.repository} />
        </Link>
      </p>
      <h1 className="mt-0.5 flex flex-wrap items-center gap-2 text-lg font-semibold">
        <span>
          Scan of <span className="font-mono">{scan.tag}</span>
        </span>
        <ScanStatusBadge status={scan.status} />
      </h1>
      <p className={`mt-1 text-xs ${mutedClass}`}>
        Digest <ShortDigest digest={scan.digest} /> · requested <Ago iso={scan.requested_at} />
        {scan.requested_by && ` by ${scan.requested_by}`}
        {scan.started_at && (
          <>
            {" "}
            · started <Ago iso={scan.started_at} />
          </>
        )}
        {scan.finished_at && (
          <>
            {" "}
            · finished <Ago iso={scan.finished_at} />
          </>
        )}
        {scan.job_name && ` · job ${scan.job_name}`}
        {resultDigest?.scanner_version && ` · Trivy ${resultDigest.scanner_version}`}
      </p>

      {scan.status === "failed" && (
        <div className="mt-3 rounded border border-red-200 bg-red-50 px-3 py-2 dark:border-red-900 dark:bg-red-950/40">
          <p className="text-xs font-medium text-red-800 dark:text-red-300">The scan failed</p>
          <ErrorText>{scan.error ?? "No error was recorded."}</ErrorText>
        </div>
      )}
      {(scan.status === "queued" || scan.status === "running") && (
        <p className={`mt-4 text-sm ${mutedClass}`}>
          This scan is {scan.status}. The diff appears here when it finishes; reload to check.
        </p>
      )}
      {scan.status === "done" && !diff && (
        <p className={`mt-4 text-sm ${mutedClass}`}>
          {comparedWith.length === 0
            ? "No workload runs this image with a known digest now, so there is nothing to compare against."
            : "The scan finished but its result is missing."}
        </p>
      )}

      {diff && (
        <>
          <p className="mt-4 text-sm font-medium">{diffSummary(diff)}</p>
          <p className={`mt-0.5 text-xs ${mutedClass}`}>
            Compared with{" "}
            {comparedWith.length > 1 ? `the union of the ${comparedWith.length} running digests` : "the running digest"}
            {comparedWith.length === 1 && (
              <>
                {" "}
                <ShortDigest digest={comparedWith[0]!.digest} />
              </>
            )}
            {runningDigests.length > 1 && (
              <span className="ml-2">
                {comparedWith.length !== runningDigests.length && (
                  <Link href={`/scans/${scan.id}`} className={`mr-1 ${linkClass}`}>
                    union
                  </Link>
                )}
                {runningDigests
                  .filter((d) => comparedWith.length !== 1 || d.id !== comparedWith[0]!.id)
                  .map((d) => (
                    <Link key={d.id} href={`/scans/${scan.id}?running=${d.id}`} className={`mr-1 font-mono ${linkClass}`}>
                      {d.digest.replace(/^sha256:/, "").slice(0, 12)}
                    </Link>
                  ))}
              </span>
            )}
          </p>

          <Section title="Fixed" count={diff.fixed.length} note="In the running image, not in this candidate.">
            {diff.fixed.length ? <VulnTable rows={diff.fixed} kev={kev} /> : <Empty>Nothing.</Empty>}
          </Section>

          <Section
            title="Still present"
            count={diff.stillPresent.length}
            note="In both. Marked rows have a fix upstream that this candidate does not include."
          >
            {diff.stillPresent.length ? (
              <Table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th className="text-right">CVSS</th>
                    <th>ID</th>
                    <th>Package</th>
                    <th>Running</th>
                    <th>Candidate</th>
                    <th>Fixed in</th>
                    <th>Title</th>
                  </tr>
                </thead>
                <tbody>
                  {diff.stillPresent.map(({ running: v, candidate: c, fixAvailableUpstream }) => (
                    <tr key={v.id}>
                      <td>
                        <SeverityBadge severity={c.severity} />
                      </td>
                      <td className="text-right">
                        <Cvss score={c.score ?? v.score} />
                      </td>
                      <td>
                        <CveLink id={v.vuln_id} link={v.link} kev={kev.get(v.vuln_id)} />
                      </td>
                      <td className="font-mono text-xs">{v.package}</td>
                      <td className="font-mono text-xs">{v.installed_version}</td>
                      <td className="font-mono text-xs">{c.installed_version}</td>
                      <td className="font-mono text-xs">
                        {v.fixed_version ?? c.fixed_version ?? <span className={mutedClass}>—</span>}
                      </td>
                      <td className="max-w-md text-xs">
                        {fixAvailableUpstream && (
                          <p className="font-medium text-amber-700 dark:text-amber-300">
                            A fix exists upstream, this candidate doesn&apos;t include it
                          </p>
                        )}
                        {v.title}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <Empty>Nothing.</Empty>
            )}
          </Section>

          <Section title="New" count={diff.introduced.length} note="In this candidate, not in the running image.">
            {diff.introduced.length ? <VulnTable rows={diff.introduced} kev={kev} /> : <Empty>Nothing.</Empty>}
          </Section>
        </>
      )}
    </div>
  );
}
