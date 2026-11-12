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
  const { pr } = await queuePullRequest(db, { scanId, requestedBy: user.username });
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
