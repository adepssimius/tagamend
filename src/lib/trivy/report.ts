import { z } from "zod";
import { type DigestScan, type Finding, normaliseSeverity } from "./finding";

/**
 * The parts of a trivy-operator `VulnerabilityReport`
 * (aquasecurity.github.io/v1alpha1) that tagamend reads. Unknown fields are
 * ignored, so a newer operator that adds fields still parses.
 */
const optionalText = z.string().nullish();

const vulnerabilitySchema = z.object({
  vulnerabilityID: z.string().min(1),
  resource: z.string(),
  installedVersion: z.string(),
  fixedVersion: optionalText,
  severity: optionalText,
  score: z.number().nullish(),
  title: optionalText,
  primaryLink: optionalText,
});

export const vulnerabilityReportSchema = z.object({
  metadata: z.object({
    name: z.string(),
    namespace: z.string(),
    labels: z.object({
      "trivy-operator.resource.kind": z.string().min(1),
      "trivy-operator.resource.name": z.string().min(1),
      "trivy-operator.resource.namespace": z.string().min(1),
      "trivy-operator.container.name": z.string().min(1),
    }),
  }),
  report: z.object({
    // Stored as `toISOString()` like every other timestamp, so it compares and
    // sorts correctly against values written with `now()`.
    updateTimestamp: z
      .string()
      .refine((v) => !Number.isNaN(Date.parse(v)), "not a timestamp")
      .transform((v) => new Date(v).toISOString()),
    scanner: z.object({ version: optionalText }).nullish(),
    registry: z.object({ server: z.string().min(1) }),
    artifact: z.object({
      repository: z.string().min(1),
      tag: optionalText,
      digest: z.string().min(1),
    }),
    os: z.object({ family: optionalText, name: optionalText }).nullish(),
    vulnerabilities: z.array(vulnerabilitySchema).nullish(),
  }),
});

/** The workload a report was made for, as trivy-operator labels it. */
export interface ReportResource {
  kind: string;
  name: string;
  namespace: string;
  container: string;
}

export interface ParsedReport {
  /** `namespace/name` of the report object, for logs. */
  id: string;
  resource: ReportResource;
  /** As trivy reports it: `index.docker.io`, `ghcr.io`, ... */
  registry: string;
  repository: string;
  tag: string | null;
  scan: DigestScan;
}

export type ParseResult = { ok: true; report: ParsedReport } | { ok: false; id: string; error: string };

const emptyToNull = (s: string | null | undefined) => (s ? s : null);

/** Validates one VulnerabilityReport and normalises it into a `DigestScan`. */
export function parseVulnerabilityReport(raw: unknown): ParseResult {
  const parsed = vulnerabilityReportSchema.safeParse(raw);
  if (!parsed.success) {
    const meta = (raw as { metadata?: { namespace?: unknown; name?: unknown } } | null)?.metadata;
    const id = `${String(meta?.namespace ?? "?")}/${String(meta?.name ?? "?")}`;
    const error = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    return { ok: false, id, error };
  }
  const { metadata, report } = parsed.data;
  const labels = metadata.labels;
  const findings: Finding[] = (report.vulnerabilities ?? []).map((v) => ({
    vulnId: v.vulnerabilityID,
    package: v.resource,
    installedVersion: v.installedVersion,
    fixedVersion: emptyToNull(v.fixedVersion),
    severity: normaliseSeverity(v.severity),
    score: v.score ?? null,
    title: emptyToNull(v.title),
    link: emptyToNull(v.primaryLink),
  }));
  return {
    ok: true,
    report: {
      id: `${metadata.namespace}/${metadata.name}`,
      resource: {
        kind: labels["trivy-operator.resource.kind"],
        name: labels["trivy-operator.resource.name"],
        namespace: labels["trivy-operator.resource.namespace"],
        container: labels["trivy-operator.container.name"],
      },
      registry: report.registry.server,
      repository: report.artifact.repository,
      tag: emptyToNull(report.artifact.tag),
      scan: {
        digest: report.artifact.digest,
        osFamily: emptyToNull(report.os?.family),
        osName: emptyToNull(report.os?.name),
        scannedAt: report.updateTimestamp,
        reportUpdatedAt: report.updateTimestamp,
        scannerVersion: emptyToNull(report.scanner?.version),
        findings,
      },
    },
  };
}
