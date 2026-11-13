"use server";

import { revalidatePath } from "next/cache";
import { requireUser } from "@/auth";
import { getDb } from "@/lib/db";
import { queuePullRequest } from "@/lib/gitops/enqueue";
import { queueScan } from "@/lib/scan/enqueue";

/** Queues a scan of a tag. The digest is read from the database, not the form. */
export async function scanTag(formData: FormData): Promise<void> {
  const user = await requireUser();
  const tagId = Number(formData.get("tagId"));
  if (!Number.isInteger(tagId)) throw new Error("scanTag: bad tagId");
  const db = await getDb();
  const tag = await db.selectFrom("tags").selectAll().where("id", "=", tagId).executeTakeFirst();
  if (!tag?.digest) throw new Error("scanTag: tag not found or has no digest");
  await queueScan(db, { imageId: tag.image_id, tag: tag.tag, digest: tag.digest, requestedBy: user.username });
  revalidatePath(`/images/${tag.image_id}`);
  revalidatePath("/status");
  revalidatePath("/");
}

/** Queues a GitOps PR that moves the image to a scanned candidate. */
export async function openPullRequest(formData: FormData): Promise<void> {
  const user = await requireUser();
  const scanId = Number(formData.get("scanId"));
  if (!Number.isInteger(scanId)) throw new Error("openPullRequest: bad scanId");
  const db = await getDb();
  // Unticking workloads narrows the PR; all ticked (or no picker) means all.
  const chosen = formData.getAll("workload").map(String);
  const all = formData.getAll("allWorkloads").map(String);
  const workloads = chosen.length && chosen.length < all.length ? chosen : null;
  const { pr } = await queuePullRequest(db, { scanId, requestedBy: user.username, workloads });
  revalidatePath(`/images/${pr.image_id}`);
  revalidatePath("/status");
}

/**
 * Scans the build a pod actually runs when it is older than what its tag
 * points to now. The digest must be one a workload of this image reports.
 */
export async function scanRunningBuild(formData: FormData): Promise<void> {
  const user = await requireUser();
  const imageId = Number(formData.get("imageId"));
  const digest = String(formData.get("digest") ?? "");
  if (!Number.isInteger(imageId)) throw new Error("scanRunningBuild: bad imageId");
  const db = await getDb();
  const w = await db
    .selectFrom("workloads")
    .select(["tag"])
    .where("image_id", "=", imageId)
    .where("pod_digest", "=", digest)
    .where("gone_at", "is", null)
    .executeTakeFirst();
  if (!w) throw new Error("scanRunningBuild: no running workload of this image uses that digest");
  await queueScan(db, { imageId, tag: w.tag ?? digest, digest, requestedBy: user.username });
  revalidatePath(`/images/${imageId}`);
  revalidatePath("/status");
}

/** Makes the image's tags due, so the worker checks them within a minute. */
export async function checkTagsNow(formData: FormData): Promise<void> {
  await requireUser();
  const imageId = Number(formData.get("imageId"));
  if (!Number.isInteger(imageId)) throw new Error("checkTagsNow: bad imageId");
  const db = await getDb();
  await db.updateTable("images").set({ last_tag_sync_at: null }).where("id", "=", imageId).execute();
  revalidatePath(`/images/${imageId}`);
}
