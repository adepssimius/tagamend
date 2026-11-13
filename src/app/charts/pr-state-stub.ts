import type { DB } from "@/lib/db";

/**
 * TEMPORARY stub. The real refreshChartPrStates lives in @/lib/gitops/pr-state
 * on feat/chart-pr. At merge, delete this file and import it from there in
 * src/app/charts/page.tsx and src/app/charts/[id]/page.tsx.
 */
export async function refreshChartPrStates(
  _db: DB,
  _opts: { repo: string | undefined; token: string | undefined; chartId?: number },
): Promise<number> {
  return 0;
}
