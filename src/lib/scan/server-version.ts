import { z } from "zod";

const versionResponse = z.object({ Version: z.string().min(1) });

/**
 * The Trivy server's version. `trivy server` answers `GET /version` with
 * `{"Version":"0.76.1","VulnerabilityDB":{...}}` (checked against 0.76.1).
 */
export async function fetchTrivyServerVersion(
  serverUrl: string,
  opts: { signal?: AbortSignal; fetch?: typeof fetch; timeoutMs?: number } = {},
): Promise<string> {
  const signals = [AbortSignal.timeout(opts.timeoutMs ?? 5000), ...(opts.signal ? [opts.signal] : [])];
  const res = await (opts.fetch ?? fetch)(new URL("/version", serverUrl), { signal: AbortSignal.any(signals) });
  if (!res.ok) throw new Error(`GET /version: HTTP ${res.status}`);
  return versionResponse.parse(await res.json()).Version;
}
