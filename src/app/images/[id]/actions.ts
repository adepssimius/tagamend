"use server";

import { revalidatePath } from "next/cache";
import { requireUser } from "@/auth";
import { getDb } from "@/lib/db";
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
