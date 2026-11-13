"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { requireUser } from "@/auth";
import { getDb } from "@/lib/db";
import { upsertImage } from "@/lib/db/store";
import type { ChartImage } from "@/lib/charts/types";
import { queueChartPullRequest } from "@/lib/gitops/chart-enqueue";
import { errorMessage } from "@/lib/log";
import { candidateChanges, candidatePins } from "@/lib/queries/charts";
import { queueScan } from "@/lib/scan/enqueue";

async function loadCandidate(formData: FormData, what: string) {
  const candidateId = Number(formData.get("candidateId"));
  if (!Number.isInteger(candidateId)) throw new Error(`${what}: bad candidateId`);
  const db = await getDb();
  const candidate = await db.selectFrom("chart_candidates").selectAll().where("id", "=", candidateId).executeTakeFirst();
  if (!candidate) throw new Error(`${what}: candidate not found`);
  return { db, candidate };
}

/**
 * Queues a scan of each image the candidate would run: every changed image
 * with a digest, and the chart's default for each pinned image. Images and
 * digests come from the database, not the form. Already queued or scanned
 * digests are left alone (queueScan returns the existing scan).
 */
export async function scanChartCandidate(formData: FormData): Promise<void> {
  const user = await requireUser();
  const { db, candidate } = await loadCandidate(formData, "scanChartCandidate");
  const targets: ChartImage[] = [
    ...candidateChanges(candidate).flatMap((c) => (c.to?.digest ? [c.to] : [])),
    ...candidatePins(candidate).flatMap((p) => (p.chartDefault?.digest ? [p.chartDefault] : [])),
  ];
  const seen = new Set<string>();
  for (const t of targets) {
    const k = `${t.registry}/${t.repository}@${t.digest}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const imageId = await upsertImage(db, t.registry, t.repository);
    await queueScan(db, { imageId, tag: t.tag ?? t.digest!, digest: t.digest!, requestedBy: user.username });
  }
  revalidatePath(`/charts/${candidate.chart_id}`);
  revalidatePath("/charts");
  revalidatePath("/status");
}

/** Queues a PR that bumps the chart to the candidate. A failure comes back to the page as a message. */
export async function openChartPullRequest(formData: FormData): Promise<void> {
  const user = await requireUser();
  const { db, candidate } = await loadCandidate(formData, "openChartPullRequest");
  const updatePins = formData.get("updatePins") === "1";
  let error: string | null = null;
  try {
    await queueChartPullRequest(db, { candidateId: candidate.id, requestedBy: user.username, updatePins });
  } catch (e) {
    error = errorMessage(e);
  }
  revalidatePath(`/charts/${candidate.chart_id}`);
  revalidatePath("/charts");
  const p = new URLSearchParams({ candidate: String(candidate.id) });
  if (error) p.set("prError", error);
  redirect(`/charts/${candidate.chart_id}?${p}#candidate`);
}

/** Makes the HelmRelease due, so the worker checks its chart within a minute. */
export async function checkChartNow(formData: FormData): Promise<void> {
  await requireUser();
  const chartId = Number(formData.get("chartId"));
  if (!Number.isInteger(chartId)) throw new Error("checkChartNow: bad chartId");
  const db = await getDb();
  await db.updateTable("charts").set({ last_sync_at: null }).where("id", "=", chartId).execute();
  revalidatePath(`/charts/${chartId}`);
  revalidatePath("/charts");
}
