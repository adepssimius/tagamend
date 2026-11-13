"use server";

import { revalidatePath } from "next/cache";
import { requireUser } from "@/auth";
import { getDb } from "@/lib/db";
import { setSettings } from "@/lib/settings";

export async function saveSettings(formData: FormData): Promise<void> {
  await requireUser();
  await setSettings(await getDb(), {
    autoScanBestCandidate: formData.get("autoScanBestCandidate") === "1",
    autoScanRunningBuild: formData.get("autoScanRunningBuild") === "1",
    fluxManagedOnly: formData.get("fluxManagedOnly") === "1",
    internalHostPatterns: String(formData.get("internalHostPatterns") ?? "")
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean),
    loadBalancerReach: formData.get("loadBalancerReach") === "internet" ? "internet" : "lan",
    oidcClientsSource: String(formData.get("oidcClientsSource") ?? "").trim(),
  });
  revalidatePath("/settings");
}
