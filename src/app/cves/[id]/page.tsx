import Link from "next/link";
import { requireUser } from "@/auth";
import {
  Empty,
  externalVulnUrl,
  ImageName,
  linkClass,
  mutedClass,
  Section,
  SeverityBadge,
  ShortDigest,
  Table,
} from "@/components/ui";
import { getDb } from "@/lib/db";
import { getCvePage } from "@/lib/queries/cve";

export const dynamic = "force-dynamic";

/** Next hands over route params still percent-encoded; a stray `%` must not 500. */
function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export default async function CvePage({ params }: { params: Promise<{ id: string }> }) {
  await requireUser();
  const { id } = await params;
  const vulnId = safeDecode(id);
  const { title, severity, score, link, affected, introducedBy } = await getCvePage(await getDb(), vulnId);

  return (
    <div>
      <h1 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
        {severity && <SeverityBadge severity={severity} />}
        <span className="font-mono">{vulnId}</span>
        {score != null && <span className={`text-sm font-normal ${mutedClass}`}>CVSS {score.toFixed(1)}</span>}
      </h1>
      {title && <p className="mt-1 text-sm">{title}</p>}
      <p className="mt-1 text-xs">
        <a href={externalVulnUrl(vulnId, link)} target="_blank" rel="noreferrer noopener" className={linkClass}>
          {externalVulnUrl(vulnId, link)} ↗
        </a>
      </p>

      <Section title="Affected images" count={affected.length} note="Images with a running digest that contains this vulnerability.">
        {affected.length === 0 ? (
          <Empty>No running image contains {vulnId}.</Empty>
        ) : (
          <div className="space-y-4">
            {affected.map((img) => (
              <div key={img.imageId} className="rounded border border-zinc-200 p-3 dark:border-zinc-800">
                <Link href={`/images/${img.imageId}`} className="text-sm hover:underline">
                  <ImageName registry={img.registry} repository={img.repository} />
                </Link>

                <div className="mt-2">
                  <Table>
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed in</th>
                        <th>Digest</th>
                      </tr>
                    </thead>
                    <tbody>
                      {img.findings.map((f) => (
                        <tr key={`${f.digestId}-${f.package}-${f.installedVersion}`}>
                          <td>
                            <SeverityBadge severity={f.severity} />
                          </td>
                          <td className="font-mono text-xs">{f.package}</td>
                          <td className="font-mono text-xs">{f.installedVersion}</td>
                          <td className="font-mono text-xs">{f.fixedVersion ?? <span className={mutedClass}>—</span>}</td>
                          <td>
                            <ShortDigest digest={f.digest} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                </div>

                <p className="mt-2 text-xs">
                  <span className={mutedClass}>Workloads: </span>
                  {img.workloads.length === 0
                    ? "none"
                    : img.workloads.map((w, i) => (
                        <span key={w.id}>
                          {i > 0 && ", "}
                          {w.namespace}/{w.kind}/{w.name}
                          {w.tag && <span className={`font-mono ${mutedClass}`}> ({w.tag})</span>}
                        </span>
                      ))}
                </p>

                <p className="mt-1 text-xs">
                  <span className={mutedClass}>Scanned candidates: </span>
                  {img.candidates.length === 0
                    ? "none"
                    : img.candidates.map((c, i) => (
                        <span key={c.scanId}>
                          {i > 0 && ", "}
                          <Link href={`/scans/${c.scanId}`} className={`font-mono ${linkClass}`}>
                            {c.tag}
                          </Link>{" "}
                          {c.fixes ? (
                            <span className="font-medium text-emerald-700 dark:text-emerald-400">fixes it</span>
                          ) : (
                            <span className={mutedClass}>still has it</span>
                          )}
                        </span>
                      ))}
                </p>
              </div>
            ))}
          </div>
        )}
      </Section>

      {introducedBy.length > 0 && (
        <Section title="Only in scanned candidates" count={introducedBy.length} note="Candidates that would bring this vulnerability into an image that does not have it now.">
          <ul className="space-y-0.5 text-sm">
            {introducedBy.map((c) => (
              <li key={c.scanId}>
                <Link href={`/images/${c.imageId}`} className="hover:underline">
                  <ImageName registry={c.registry} repository={c.repository} />
                </Link>{" "}
                <Link href={`/scans/${c.scanId}`} className={`font-mono text-xs ${linkClass}`}>
                  {c.tag}
                </Link>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
