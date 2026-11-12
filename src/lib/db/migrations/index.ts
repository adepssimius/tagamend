import type { Migration } from "kysely/migration";
import * as m001 from "./001_initial";
import * as m002 from "./002_pull_requests";
import * as m003 from "./003_kev";
import * as m004 from "./004_pod_digest";
import * as m005 from "./005_pr_state";
import * as m006 from "./006_pr_workloads";

/**
 * Migrations are imported statically, not read from a folder at runtime, so
 * that the bundled worker and the Next.js server both carry them.
 * Add new ones here in order. Never edit one that has shipped.
 */
export const migrations: Record<string, Migration> = {
  "001_initial": m001,
  "002_pull_requests": m002,
  "003_kev": m003,
  "004_pod_digest": m004,
  "005_pr_state": m005,
  "006_pr_workloads": m006,
};
