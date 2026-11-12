import type { DB } from "../db";
import type { Kev } from "../db/schema";

/** The KEV entries among `ids`, by CVE id. */
export async function kevFor(db: DB, ids: Iterable<string>): Promise<Map<string, Kev>> {
  const unique = [...new Set(ids)].filter((id) => id.startsWith("CVE-"));
  const out = new Map<string, Kev>();
  for (let i = 0; i < unique.length; i += 500) {
    for (const k of await db.selectFrom("kev").selectAll().where("cve_id", "in", unique.slice(i, i + 500)).execute()) {
      out.set(k.cve_id, k);
    }
  }
  return out;
}
