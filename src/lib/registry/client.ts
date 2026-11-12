import { createHash } from "node:crypto";
import { anonymous, type Credential, type CredentialLookup } from "./credentials";
import {
  parseRetryAfter,
  RegistryAuthError,
  RegistryError,
  RegistryNotFoundError,
  RegistryRateLimitError,
} from "./errors";
import { apiHost } from "./hosts";

/**
 * A small OCI distribution client: tag listing and manifest digests, with the
 * bearer-token challenge that Docker Hub, ghcr.io, quay.io and registry.k8s.io
 * use. Uses `fetch` and follows redirects itself, so that a token issued for
 * one host is never sent to another.
 */

export const MANIFEST_ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

const USER_AGENT = "tagamend";
const PAGE_SIZE = 1000;
/**
 * A guard against a registry that links pages forever, not a size limit:
 * immich-app/immich-machine-learning alone has over 60,000 tags on ghcr.io
 * (1,000 per page), one per commit, PR and hardware variant.
 */
const MAX_PAGES = 1000;
const MAX_REDIRECTS = 5;
/** Token lifetime when the token response does not say (the distribution spec's default). */
const DEFAULT_TOKEN_SECONDS = 60;
/** Treat a token as expired this long before it is. */
const TOKEN_SKEW_MS = 10_000;

export interface RegistryClientOptions {
  fetch?: typeof fetch;
  credentials?: CredentialLookup;
  /** Aborts every request in flight. */
  signal?: AbortSignal;
  /** Per request. */
  timeoutMs?: number;
  now?: () => number;
}

export interface Challenge {
  scheme: string;
  params: Record<string, string>;
}

/** Parses `Bearer realm="...",service="...",scope="..."`. Quoted values may contain commas. */
export function parseChallenge(header: string): Challenge | undefined {
  const m = /^\s*(\w+)\s*(.*)$/s.exec(header);
  if (!m) return undefined;
  const params: Record<string, string> = {};
  const re = /([\w-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  for (let p = re.exec(m[2]!); p; p = re.exec(m[2]!)) {
    params[p[1]!.toLowerCase()] = p[2] !== undefined ? p[2].replace(/\\(.)/g, "$1") : p[3]!;
  }
  return { scheme: m[1]!.toLowerCase(), params };
}

/** The `rel="next"` URL of a Link header, if any. */
export function nextLink(header: string | null): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(/,(?=\s*<)/)) {
    const m = /<([^>]*)>\s*(.*)$/.exec(part.trim());
    if (m && /rel\s*=\s*"?next"?/i.test(m[2]!)) return m[1];
  }
  return undefined;
}

interface CachedAuth {
  header: string;
  expiresAt: number;
}

export class RegistryClient {
  private readonly fetchImpl: typeof fetch;
  private readonly credentials: CredentialLookup;
  private readonly signal: AbortSignal | undefined;
  private readonly timeoutMs: number;
  private readonly now: () => number;
  /** Authorization header by `host scope`, so the first request after a challenge does not repeat it. */
  private readonly auth = new Map<string, CachedAuth>();
  /** Tokens by realm, service, scope and user. */
  private readonly tokens = new Map<string, CachedAuth>();

  constructor(opts: RegistryClientOptions = {}) {
    this.fetchImpl = opts.fetch ?? fetch;
    this.credentials = opts.credentials ?? anonymous;
    this.signal = opts.signal;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.now = opts.now ?? Date.now;
  }

  /** Every tag of a repository, following `Link` pagination. */
  async listTags(registry: string, repository: string): Promise<string[]> {
    let url: URL | undefined = new URL(`https://${apiHost(registry)}/v2/${repository}/tags/list?n=${PAGE_SIZE}`);
    const tags: string[] = [];
    for (let page = 0; url; page++) {
      if (page >= MAX_PAGES) throw new RegistryError("other", url.host, `more than ${MAX_PAGES} pages of tags for ${repository}`);
      const { res, url: finalUrl } = await this.request(registry, repository, url, "GET", "application/json");
      const body = (await res.json()) as { tags?: string[] | null };
      for (const t of body.tags ?? []) if (typeof t === "string") tags.push(t);
      const next = nextLink(res.headers.get("link"));
      url = next ? new URL(next, finalUrl) : undefined;
    }
    return [...new Set(tags)];
  }

  /**
   * The digest a tag (or digest) resolves to, from `Docker-Content-Digest` on
   * a HEAD. For a multi-platform image this is the index digest, the same one
   * a runtime records when it pulls by tag.
   */
  async headManifest(registry: string, repository: string, ref: string): Promise<string> {
    const url = new URL(`https://${apiHost(registry)}/v2/${repository}/manifests/${ref}`);
    const { res } = await this.request(registry, repository, url, "HEAD", MANIFEST_ACCEPT);
    const digest = res.headers.get("docker-content-digest");
    if (digest) return digest;
    // A registry that omits the header on HEAD: hash the manifest body instead.
    const { res: got } = await this.request(registry, repository, url, "GET", MANIFEST_ACCEPT);
    const bytes = Buffer.from(await got.arrayBuffer());
    return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  }

  private async request(
    registry: string,
    repository: string,
    start: URL,
    method: "GET" | "HEAD",
    accept: string,
  ): Promise<{ res: Response; url: URL }> {
    const originHost = start.host;
    const scope = `repository:${repository}:pull`;
    let url = start;
    let redirects = 0;
    let challenged = false;
    for (;;) {
      const key = `${url.host} ${scope}`;
      const cached = this.auth.get(key);
      const headers: Record<string, string> = { Accept: accept, "User-Agent": USER_AGENT };
      if (cached && cached.expiresAt > this.now()) headers.Authorization = cached.header;

      const res = await this.fetchOnce(url, { method, headers });

      if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
        await drain(res);
        if (++redirects > MAX_REDIRECTS) throw new RegistryError("other", url.host, `too many redirects from ${start}`);
        url = new URL(res.headers.get("location")!, url);
        challenged = false;
        continue;
      }

      if (res.status === 401 && !challenged) {
        const header = res.headers.get("www-authenticate");
        await drain(res);
        if (!header) throw new RegistryAuthError(url.host, `${url.host} answered 401 with no challenge`, 401);
        // Credentials belong to the registry the image names, so they are only
        // offered to a challenge from that registry's own API host.
        const cred = url.host === originHost ? await this.credentials(registry) : undefined;
        // A 401 on a request that carried a token means that token is no good,
        // however long it claimed to last.
        const value = await this.answerChallenge(url.host, header, scope, cred, headers.Authorization !== undefined);
        this.auth.set(key, value);
        challenged = true;
        continue;
      }

      if (res.ok) return { res, url };
      throw await this.toError(url, res, await this.hasCredentials(registry));
    }
  }

  private async hasCredentials(registry: string): Promise<boolean> {
    return (await this.credentials(registry)) !== undefined;
  }

  private async answerChallenge(
    host: string,
    header: string,
    scope: string,
    cred: Credential | undefined,
    refresh: boolean,
  ): Promise<CachedAuth> {
    const ch = parseChallenge(header);
    if (ch?.scheme === "basic") {
      if (!cred) throw new RegistryAuthError(host, `${host} requires credentials (Basic) and none are configured`, 401);
      return { header: basic(cred), expiresAt: Number.POSITIVE_INFINITY };
    }
    if (ch?.scheme !== "bearer" || !ch.params.realm) {
      throw new RegistryAuthError(host, `${host} sent an unsupported challenge: ${ch?.scheme ?? "unparseable"}`, 401);
    }
    const realm = new URL(ch.params.realm);
    if (realm.protocol !== "https:") throw new RegistryAuthError(host, `${host} sent a non-https token realm`, 401);
    const wantScope = ch.params.scope ?? scope;
    const tokenKey = `${realm} ${ch.params.service ?? ""} ${wantScope} ${cred?.username ?? ""}`;
    const cached = this.tokens.get(tokenKey);
    if (cached && !refresh && cached.expiresAt > this.now()) return cached;

    if (ch.params.service) realm.searchParams.set("service", ch.params.service);
    realm.searchParams.set("scope", wantScope);
    const headers: Record<string, string> = { "User-Agent": USER_AGENT };
    if (cred) headers.Authorization = basic(cred);
    const res = await this.fetchOnce(realm, { method: "GET", headers });
    if (!res.ok) throw await this.toError(realm, res, cred !== undefined, "token request");
    const body = (await res.json()) as { token?: string; access_token?: string; expires_in?: number; issued_at?: string };
    const token = body.token ?? body.access_token;
    if (!token) throw new RegistryAuthError(realm.host, `token response from ${realm.host} has no token`, res.status);
    const issued = body.issued_at ? Date.parse(body.issued_at) : NaN;
    const from = Number.isNaN(issued) ? this.now() : Math.min(issued, this.now());
    const seconds = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : DEFAULT_TOKEN_SECONDS;
    const value = { header: `Bearer ${token}`, expiresAt: from + seconds * 1000 - TOKEN_SKEW_MS };
    this.tokens.set(tokenKey, value);
    return value;
  }

  private async fetchOnce(url: URL, init: { method: string; headers: Record<string, string> }): Promise<Response> {
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const signal = this.signal ? AbortSignal.any([this.signal, timeout]) : timeout;
    try {
      return await this.fetchImpl(url, { ...init, redirect: "manual", signal });
    } catch (e) {
      if (this.signal?.aborted) throw e;
      const msg = e instanceof Error ? (e.name === "TimeoutError" ? `timed out after ${this.timeoutMs}ms` : e.message) : String(e);
      throw new RegistryError("other", url.host, `${init.method} ${url.host}${url.pathname}: ${msg}`);
    }
  }

  private async toError(url: URL, res: Response, hasCredentials: boolean, what = `${url.pathname}`): Promise<RegistryError> {
    const text = await res.text().catch(() => "");
    const codes = registryErrorCodes(text);
    const detail = codes.length ? codes.join(", ") : text.slice(0, 200).replace(/\s+/g, " ").trim();
    const msg = `${url.host} ${what}: HTTP ${res.status}${detail ? ` (${detail})` : ""}`;
    if (res.status === 429 || codes.includes("TOOMANYREQUESTS")) {
      return new RegistryRateLimitError(url.host, msg, res.status, parseRetryAfter(res.headers.get("retry-after"), this.now()));
    }
    if (res.status === 404 || codes.some((c) => c === "NAME_UNKNOWN" || c === "MANIFEST_UNKNOWN")) {
      return new RegistryNotFoundError(url.host, msg, res.status);
    }
    if (res.status === 401 || res.status === 403 || codes.some((c) => c === "UNAUTHORIZED" || c === "DENIED")) {
      return new RegistryAuthError(url.host, hasCredentials ? msg : `${msg}; no credentials are configured`, res.status);
    }
    return new RegistryError("other", url.host, msg, res.status);
  }
}

function basic(cred: Credential): string {
  return `Basic ${Buffer.from(`${cred.username}:${cred.password}`).toString("base64")}`;
}

/** The `code`s of an OCI error body: `{"errors":[{"code":"..."}]}`. */
function registryErrorCodes(text: string): string[] {
  try {
    const body = JSON.parse(text) as { errors?: { code?: unknown }[] };
    return (body.errors ?? []).map((e) => e.code).filter((c): c is string => typeof c === "string");
  } catch {
    return [];
  }
}

async function drain(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // nothing to release
  }
}
