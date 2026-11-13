import { requireUser } from "@/auth";
import { SubmitButton } from "@/components/submit-button";
import { mutedClass, Section } from "@/components/ui";
import { getDb } from "@/lib/db";
import { getSettings } from "@/lib/settings";
import { saveSettings } from "./actions";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  await requireUser();
  const s = await getSettings(await getDb());
  return (
    <div className="max-w-2xl">
      <h1 className="text-lg font-semibold">Settings</h1>
      <form action={saveSettings}>
        <Section title="Automatic scans">
          <div className="space-y-4 text-sm">
            <label className="flex gap-2">
              <input type="checkbox" name="autoScanBestCandidate" value="1" defaultChecked={s.autoScanBestCandidate} className="mt-1" />
              <span>
                <span className="font-medium">Scan each image&apos;s best candidate</span>
                <span className={`block text-xs ${mutedClass}`}>
                  The candidate the Overview shows. It is scanned within a few minutes of tag discovery finding it,
                  so its diff is ready when you look. Scans run one at a time (SCAN_CONCURRENCY) and pull the image
                  from its registry, which counts against Docker Hub&apos;s rate limit.
                </span>
              </span>
            </label>
            <label className="flex gap-2">
              <input type="checkbox" name="autoScanRunningBuild" value="1" defaultChecked={s.autoScanRunningBuild} className="mt-1" />
              <span>
                <span className="font-medium">Scan the build a pod runs when it is older than its tag</span>
                <span className={`block text-xs ${mutedClass}`}>
                  trivy-operator scans what a tag points to now. This scans what the pod actually runs, so its CVEs
                  are the real ones and the tag&apos;s newer build appears as a candidate.
                </span>
              </span>
            </label>
            <p className={`text-xs ${mutedClass}`}>
              A digest that was scanned before, including a failed scan, is not scanned again automatically. Use Retry
              on the image page.
            </p>
          </div>
        </Section>
        <div className="mt-4">
          <SubmitButton pendingText="Saving…">Save</SubmitButton>
        </div>
      </form>
    </div>
  );
}
