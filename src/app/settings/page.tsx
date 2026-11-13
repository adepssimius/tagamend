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
        <Section title="Scope">
          <label className="flex gap-2 text-sm">
            <input type="checkbox" name="fluxManagedOnly" value="1" defaultChecked={s.fluxManagedOnly} className="mt-1" />
            <span>
              <span className="font-medium">Only workloads Flux manages</span>
              <span className={`block text-xs ${mutedClass}`}>
                Leaves out workloads that no Flux Kustomization or HelmRelease applies: things deployed by hand,
                one-off Jobs, k3s&apos;s bundled add-ons, and objects an operator creates on its own. Counts, lists,
                tag discovery and automatic scans all follow this. A workload whose manager cannot be read stays in.
              </span>
            </span>
          </label>
        </Section>
        <Section title="Exposure">
          <div className="space-y-4 text-sm">
            <label className="block">
              <span className="font-medium">Internal host patterns</span>
              <span className={`block text-xs ${mutedClass}`}>
                One per line. Ingress hosts that match are reachable only from the local network; others count as
                reachable from the internet. <code>*</code> matches one or more DNS labels, as in{" "}
                <code>*.internal.example.com</code>.
              </span>
              <textarea
                name="internalHostPatterns"
                rows={3}
                defaultValue={s.internalHostPatterns.join("\n")}
                className="mt-1 w-full rounded border border-zinc-300 bg-white px-2 py-1 font-mono text-xs dark:border-zinc-700 dark:bg-zinc-900"
              />
            </label>
            <label className="block">
              <span className="font-medium">LoadBalancer and NodePort services are reachable from</span>
              <select
                name="loadBalancerReach"
                defaultValue={s.loadBalancerReach}
                className="mt-1 block rounded border border-zinc-300 bg-white px-2 py-1 text-sm dark:border-zinc-700 dark:bg-zinc-900"
              >
                <option value="lan">The local network</option>
                <option value="internet">The internet</option>
              </select>
            </label>
            <label className="block">
              <span className="font-medium">OIDC client source</span>
              <span className={`block text-xs ${mutedClass}`}>
                A ConfigMap that configures your OIDC provider&apos;s clients, as <code>namespace/name/key</code>. An
                Ingress host that appears in a client&apos;s <code>redirect_uris</code> is shown as logging in through
                OIDC. Empty turns this off. The worker needs read access to that ConfigMap.
              </span>
              <input
                name="oidcClientsSource"
                defaultValue={s.oidcClientsSource}
                placeholder="namespace/configmap/key"
                className="mt-1 w-full rounded border border-zinc-300 bg-white px-2 py-1 font-mono text-xs dark:border-zinc-700 dark:bg-zinc-900"
              />
            </label>
            <p className={`text-xs ${mutedClass}`}>
              Forward auth is read from each Ingress&apos;s <code>auth-url</code> annotation, and a Tailscale ingress
              class counts as the tailnet. Changes apply at the next exposure check, within five minutes.
            </p>
          </div>
        </Section>
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
