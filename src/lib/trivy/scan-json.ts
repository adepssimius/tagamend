import { z } from "zod";
import { type DigestScan, type Finding, normaliseSeverity } from "./finding";

/**
 * `trivy image --format json` output (SchemaVersion 2), reduced to the fields
 * tagamend stores. Unknown keys are ignored, so a newer trivy that adds fields
 * still parses.
 */
const cvss = z.object({ V3Score: z.number().nullish(), V2Score: z.number().nullish() });

const vulnerability = z.object({
  VulnerabilityID: z.string().min(1),
  PkgName: z.string().min(1),
  InstalledVersion: z.string().default(""),
  FixedVersion: z.string().nullish(),
  Severity: z.string().nullish(),
  SeveritySource: z.string().nullish(),
  Title: z.string().nullish(),
  PrimaryURL: z.string().nullish(),
  CVSS: z.record(z.string(), cvss).nullish(),
});

const result = z.object({
  Target: z.string(),
  Class: z.string().nullish(),
  Type: z.string().nullish(),
  Vulnerabilities: z.array(vulnerability).nullish(),
});

export const trivyScanSchema = z.object({
  SchemaVersion: z.literal(2),
  CreatedAt: z.string().nullish(),
  ArtifactName: z.string(),
  ArtifactType: z.string().nullish(),
  Trivy: z
    .object({
      Version: z.string().nullish(),
      Server: z.object({ Version: z.string().nullish() }).nullish(),
    })
    .nullish(),
  Metadata: z
    .object({
      OS: z.object({ Family: z.string().nullish(), Name: z.string().nullish() }).nullish(),
      RepoDigests: z.array(z.string()).nullish(),
    })
    .nullish(),
  // Absent when the image has no OS and no language packages trivy recognises.
  Results: z.array(result).nullish(),
});

export type TrivyScanJson = z.infer<typeof trivyScanSchema>;

type Vuln = z.infer<typeof vulnerability>;

/** The severity source's CVSS v3 score, else NVD's, else any v3 score. */
function score(v: Vuln): number | null {
  const c = v.CVSS ?? {};
  const pick = (k: string | null | undefined) => (k ? c[k]?.V3Score : undefined) ?? undefined;
  const s = pick(v.SeveritySource) ?? pick("nvd") ?? Object.values(c).find((x) => x.V3Score != null)?.V3Score;
  return s ?? null;
}

function toFinding(v: Vuln): Finding {
  return {
    vulnId: v.VulnerabilityID,
    package: v.PkgName,
    installedVersion: v.InstalledVersion,
    fixedVersion: v.FixedVersion || null,
    severity: normaliseSeverity(v.Severity),
    score: score(v),
    title: v.Title || null,
    link: v.PrimaryURL || null,
  };
}

/**
 * Pulls the JSON document out of a scan's output. trivy writes the report to
 * stdout and logs to stderr; a Job's pod log interleaves both, so anything
 * before the first line that opens the document is dropped.
 */
export function extractJson(output: string): unknown {
  const nl = output.indexOf("\n{");
  const start = output.startsWith("{") ? 0 : nl < 0 ? -1 : nl + 1;
  const end = output.lastIndexOf("}");
  if (start < 0 || end < start) throw new Error("scan output contains no JSON document");
  return JSON.parse(output.slice(start, end + 1));
}

/**
 * Parses a candidate scan into a `DigestScan` for `storeDigest`.
 *
 * `digest` is the digest that was requested (the one listed by discovery),
 * not trivy's `ArtifactID`, which is the image config's digest.
 */
export function parseTrivyScan(input: unknown, digest: string): DigestScan {
  const doc = trivyScanSchema.parse(typeof input === "string" ? extractJson(input) : input);
  const findings = (doc.Results ?? []).flatMap((r) => (r.Vulnerabilities ?? []).map(toFinding));
  const created = doc.CreatedAt ? new Date(doc.CreatedAt) : new Date();
  return {
    digest,
    osFamily: doc.Metadata?.OS?.Family ?? null,
    osName: doc.Metadata?.OS?.Name ?? null,
    scannedAt: (Number.isNaN(created.getTime()) ? new Date() : created).toISOString(),
    reportUpdatedAt: null,
    // In client/server mode the server's version is the one whose DB matched.
    scannerVersion: doc.Trivy?.Server?.Version ?? doc.Trivy?.Version ?? null,
    findings,
  };
}
