import { z } from "zod";
import { getKv, setKv } from "../db/store";
import { KV } from "../kv-keys";
import type { WorkerContext } from "../worker-context";

const feed = z.object({
  catalogVersion: z.string(),
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      vulnerabilityName: z.string().nullish(),
      vendorProject: z.string().nullish(),
      product: z.string().nullish(),
      dateAdded: z.string(),
      dueDate: z.string().nullish(),
      knownRansomwareCampaignUse: z.string().nullish(),
      shortDescription: z.string().nullish(),
    }),
  ),
});

/**
 * Loads CISA's Known Exploited Vulnerabilities catalog into `kev`. The catalog
 * is small (under 2 MB, a few thousand entries), so it is replaced whole, and
 * skipped when its catalogVersion has not changed.
 */
export async function syncKev(ctx: WorkerContext, fetchImpl: typeof fetch = fetch): Promise<Record<string, unknown>> {
  const url = ctx.config.KEV_URL;
  if (!url) return { skipped: "KEV_URL is empty" };
  const res = await fetchImpl(url, { headers: { "User-Agent": "tagamend" }, signal: ctx.signal });
  if (!res.ok) throw new Error(`KEV feed: ${res.status} ${res.statusText}`);
  const data = feed.parse(await res.json());
  if ((await getKv(ctx.db, KV.kevCatalogVersion)) === data.catalogVersion) {
    return { unchanged: data.catalogVersion, entries: data.vulnerabilities.length };
  }
  const rows = new Map(
    data.vulnerabilities.map((v) => [
      v.cveID,
      {
        cve_id: v.cveID,
        vulnerability_name: v.vulnerabilityName ?? null,
        vendor_project: v.vendorProject ?? null,
        product: v.product ?? null,
        date_added: v.dateAdded,
        due_date: v.dueDate ?? null,
        known_ransomware: v.knownRansomwareCampaignUse === "Known" ? 1 : 0,
        short_description: v.shortDescription ?? null,
      },
    ]),
  );
  await ctx.db.transaction().execute(async (trx) => {
    await trx.deleteFrom("kev").execute();
    const all = [...rows.values()];
    for (let i = 0; i < all.length; i += 500) await trx.insertInto("kev").values(all.slice(i, i + 500)).execute();
  });
  await setKv(ctx.db, KV.kevCatalogVersion, data.catalogVersion);
  return { loaded: data.catalogVersion, entries: rows.size };
}
