import { SEVERITY_ORDER, type Severity } from "../config";

/**
 * One vulnerability finding, normalised from either a VulnerabilityReport
 * (operator) or `trivy image --format json` output (candidate scan). Both
 * parsers produce this shape and everything downstream uses only this.
 */
export interface Finding {
  vulnId: string;
  package: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: Severity;
  score: number | null;
  title: string | null;
  link: string | null;
}

/** A scanned digest and its findings, ready to store. */
export interface DigestScan {
  digest: string;
  osFamily: string | null;
  osName: string | null;
  /** When the scan ran. */
  scannedAt: string;
  /** VulnerabilityReport updateTimestamp; null for candidate scans. */
  reportUpdatedAt: string | null;
  scannerVersion: string | null;
  findings: Finding[];
}

export function normaliseSeverity(s: string | undefined | null): Severity {
  const up = (s ?? "").toUpperCase();
  return (SEVERITY_ORDER as readonly string[]).includes(up) ? (up as Severity) : "UNKNOWN";
}

/** The identity used by the diff and by the vulnerabilities unique constraint. */
export const findingKey = (f: Pick<Finding, "vulnId" | "package">) => `${f.vulnId}\u0000${f.package}`;
