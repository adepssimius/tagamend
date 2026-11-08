import { findingKey } from "./finding";

/** The fields the diff needs; `vulnerabilities` rows satisfy this. */
export interface DiffVuln {
  vuln_id: string;
  package: string;
  installed_version: string;
  fixed_version: string | null;
  severity: string;
  title: string | null;
}

export interface StillPresent<V extends DiffVuln> {
  running: V;
  candidate: V;
  /** The running image's report already names a fixed version: a fix exists
   *  upstream, but this candidate does not include it yet. */
  fixAvailableUpstream: boolean;
}

export interface Diff<V extends DiffVuln> {
  fixed: V[];
  stillPresent: StillPresent<V>[];
  introduced: V[];
}

/** Compares a candidate's vulnerabilities with the running digest's, keyed by (vuln_id, package). */
export function diffVulnerabilities<V extends DiffVuln>(running: V[], candidate: V[]): Diff<V> {
  const key = (v: V) => findingKey({ vulnId: v.vuln_id, package: v.package });
  const cand = new Map(candidate.map((v) => [key(v), v]));
  const run = new Map(running.map((v) => [key(v), v]));
  const fixed: V[] = [];
  const stillPresent: StillPresent<V>[] = [];
  for (const [k, v] of run) {
    const c = cand.get(k);
    if (!c) fixed.push(v);
    else stillPresent.push({ running: v, candidate: c, fixAvailableUpstream: !!v.fixed_version });
  }
  const introduced = [...cand].filter(([k]) => !run.has(k)).map(([, v]) => v);
  return { fixed, stillPresent, introduced };
}

export function diffSummary(d: Diff<DiffVuln>): string {
  return `fixes ${d.fixed.length}, leaves ${d.stillPresent.length}, adds ${d.introduced.length}`;
}
