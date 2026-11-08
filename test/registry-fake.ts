/** A fake OCI registry behind a stubbed `fetch`, for client and tag-sync tests. */

export interface FakeRepo {
  tags: string[];
  /** Digest by tag; tags with no entry get a stable made-up digest. */
  digests?: Record<string, string>;
}

export interface FakeHost {
  repos: Record<string, FakeRepo>;
  /** Where the token challenge points. Omit for a registry with no auth. */
  realm?: string;
  service?: string;
  pageSize?: number;
  /** Answer with a relative `Link` (ghcr, Docker Hub); else absolute. */
  absoluteLinks?: boolean;
}

export interface Call {
  method: string;
  url: string;
  authorization: string | undefined;
  accept: string | undefined;
}

export type Intercept = (call: Call) => Response | undefined;

const respond = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(status === 204 ? null : typeof body === "string" ? body : JSON.stringify(body), { status, headers });

export function digestOf(repo: FakeRepo, tag: string): string {
  return repo.digests?.[tag] ?? `sha256:${Buffer.from(tag).toString("hex").padEnd(64, "0").slice(0, 64)}`;
}

export interface FakeRegistry {
  fetch: typeof fetch;
  calls: Call[];
  count: (pred: (c: Call) => boolean) => number;
  /** Runs before normal handling; return a Response to take over the call. */
  intercept: Intercept | undefined;
  tokenSeconds: number;
  tokenBody: () => Record<string, unknown>;
}

export function fakeRegistry(hosts: Record<string, FakeHost>, tokenHosts: string[] = []): FakeRegistry {
  const reg: FakeRegistry = {
    calls: [],
    count: (pred) => reg.calls.filter(pred).length,
    intercept: undefined,
    tokenSeconds: 300,
    tokenBody: () => ({ token: `token-${reg.count((c) => tokenHosts.includes(new URL(c.url).host))}`, expires_in: reg.tokenSeconds }),
    fetch: (async (input: URL | RequestInfo, init?: RequestInit) => {
      const url = new URL(String(input));
      const headers = new Headers(init?.headers);
      const method = init?.method ?? "GET";
      const call: Call = {
        method,
        url: url.toString(),
        authorization: headers.get("authorization") ?? undefined,
        accept: headers.get("accept") ?? undefined,
      };
      reg.calls.push(call);
      const taken = reg.intercept?.(call);
      if (taken) return taken;

      if (tokenHosts.includes(url.host)) return respond(200, reg.tokenBody());

      const host = hosts[url.host];
      if (!host) throw new Error(`fake registry: unexpected host ${url.host}`);

      const tags = /^\/v2\/(.+)\/tags\/list$/.exec(url.pathname);
      const manifest = /^\/v2\/(.+)\/manifests\/(.+)$/.exec(url.pathname);
      const name = (tags ?? manifest)?.[1];
      if (!name) return respond(404, { errors: [{ code: "NOT_FOUND" }] });

      if (host.realm && !call.authorization?.startsWith("Bearer ")) {
        return respond(401, { errors: [{ code: "UNAUTHORIZED" }] }, {
          "www-authenticate": `Bearer realm="${host.realm}",service="${host.service ?? url.host}",scope="repository:${name}:pull"`,
        });
      }

      const repo = host.repos[name];
      if (!repo) return respond(404, { errors: [{ code: "NAME_UNKNOWN" }] });

      if (manifest) {
        const ref = manifest[2]!;
        if (!repo.tags.includes(ref)) return respond(404, { errors: [{ code: "MANIFEST_UNKNOWN" }] });
        return respond(200, method === "HEAD" ? "" : "{}", { "docker-content-digest": digestOf(repo, ref) });
      }

      const size = Math.min(host.pageSize ?? Number.MAX_SAFE_INTEGER, Number(url.searchParams.get("n") ?? Number.MAX_SAFE_INTEGER));
      const last = url.searchParams.get("last");
      const from = last ? repo.tags.indexOf(last) + 1 : 0;
      const page = repo.tags.slice(from, from + size);
      const hdrs: Record<string, string> = {};
      if (from + size < repo.tags.length) {
        const next = `/v2/${name}/tags/list?last=${encodeURIComponent(page.at(-1)!)}&n=${size}`;
        hdrs.link = `<${host.absoluteLinks ? `https://${url.host}${next}` : next}>; rel="next"`;
      }
      return respond(200, { name, tags: page }, hdrs);
    }) as typeof fetch,
  };
  return reg;
}
