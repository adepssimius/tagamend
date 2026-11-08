/** Keys in the `kv` table. */
export const KV = {
  /** Trivy version seen in the newest VulnerabilityReport (report sync writes it). */
  trivyReportVersion: "trivy_report_version",
  /** Trivy server version, if the scan runner can read it. */
  trivyServerVersion: "trivy_server_version",
} as const;
