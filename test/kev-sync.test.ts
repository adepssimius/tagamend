import { afterEach, describe, expect, it } from "vitest";
import { getConfig } from "@/lib/config";
import type { DB } from "@/lib/db";
import { syncKev } from "@/lib/kev/sync";
import { log } from "@/lib/log";
import { kevFor } from "@/lib/queries/kev";
import { freshDb, testDatabases } from "./helpers";

const feed = (version: string, ids: string[]) =>
  ({
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => ({
      catalogVersion: version,
      vulnerabilities: ids.map((id, i) => ({
        cveID: id,
        vendorProject: "v",
        product: "p",
        vulnerabilityName: `name ${id}`,
        dateAdded: "2026-01-0" + (i + 1),
        dueDate: "2026-02-01",
        knownRansomwareCampaignUse: i === 0 ? "Known" : "Unknown",
        shortDescription: "d",
        requiredAction: "patch",
        notes: "",
        cwes: [],
      })),
    }),
  }) as unknown as Response;

for (const { name, url } of testDatabases()) {
  describe(`KEV sync (${name})`, () => {
    let db: DB;
    afterEach(async () => db?.destroy());

    it("loads the catalog, skips an unchanged version, and replaces it whole", async () => {
      db = await freshDb(url);
      const ctx = { db, config: getConfig({ DATABASE_URL: ":memory:" }), log, signal: new AbortController().signal };
      expect(await syncKev(ctx, async () => feed("2026.11.10", ["CVE-1", "CVE-2"]))).toEqual({ loaded: "2026.11.10", entries: 2 });
      expect(await syncKev(ctx, async () => feed("2026.11.10", ["CVE-1", "CVE-2"]))).toEqual({ unchanged: "2026.11.10", entries: 2 });
      const k = await kevFor(db, ["CVE-1", "CVE-3", "GHSA-x"]);
      expect([...k.keys()]).toEqual(["CVE-1"]);
      expect(k.get("CVE-1")).toMatchObject({ known_ransomware: 1, date_added: "2026-01-01" });

      await syncKev(ctx, async () => feed("2026.11.11", ["CVE-3"]));
      expect([...(await kevFor(db, ["CVE-1", "CVE-3"])).keys()]).toEqual(["CVE-3"]);
    });
  });
}
