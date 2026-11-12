import type { Migration } from "kysely/migration";
import * as m001 from "./001_initial";
import * as m002 from "./002_pull_requests";

/**
 * Migrations are imported statically, not read from a folder at runtime, so
 * that the bundled worker and the Next.js server both carry them.
 * Add new ones here in order. Never edit one that has shipped.
 */
export const migrations: Record<string, Migration> = {
  "001_initial": m001,
  "002_pull_requests": m002,
};
