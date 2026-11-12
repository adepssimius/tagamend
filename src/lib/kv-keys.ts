/** Keys in the `kv` table. */
export const KV = {
  /** Trivy version seen in the newest VulnerabilityReport (report sync writes it). */
  trivyReportVersion: "trivy_report_version",
  /** Trivy server version, if the scan runner can read it. */
  trivyServerVersion: "trivy_server_version",
  /** catalogVersion of the CISA KEV feed last loaded. */
  kevCatalogVersion: "kev_catalog_version",
} as const;
