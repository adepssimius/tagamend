import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { MANIFEST_ACCEPT, nextLink, parseChallenge, RegistryClient } from "@/lib/registry/client";
import { fileCredentials } from "@/lib/registry/credentials";
import { RegistryAuthError, RegistryNotFoundError, RegistryRateLimitError } from "@/lib/registry/errors";
import { apiHost, parseImageRef } from "@/lib/registry/hosts";
import { digestOf, fakeRegistry, type FakeHost } from "./registry-fake";

const REALM = "https://auth.example.test/token";
const repo = { tags: ["1.0.0", "1.1.0", "2.0.0", "latest"] };
const host = (over: Partial<FakeHost> = {}): FakeHost => ({ repos: { "library/app": repo }, realm: REALM, service: "svc", ...over });
const hub = (h = host()) => fakeRegistry({ "registry-1.docker.io": h }, ["auth.example.test"]);
const client = (r: ReturnType<typeof fakeRegistry>, extra: ConstructorParameters<typeof RegistryClient>[0] = {}) =>
  new RegistryClient({ fetch: r.fetch, ...extra });

describe("hosts", () => {
  it("maps Docker Hub's names to its API host and leaves others alone", () => {
    expect(apiHost("index.docker.io")).toBe("registry-1.docker.io");
    expect(apiHost("docker.io")).toBe("registry-1.docker.io");
    for (const h of ["ghcr.io", "quay.io", "lscr.io", "mirror.gcr.io", "registry.k8s.io", "nvcr.io"]) expect(apiHost(h)).toBe(h);
  });

  it.each([
    ["alpine:3.22", "index.docker.io", "library/alpine", "3.22", null],
    ["docker.io/grafana/loki:3.0.0", "index.docker.io", "grafana/loki", "3.0.0", null],
    ["ghcr.io/a/b/c:1", "ghcr.io", "a/b/c", "1", null],
    ["localhost:5000/x:1", "localhost:5000", "x", "1", null],
    ["reg.example:5000/x", "reg.example:5000", "x", null, null],
    ["x/y@sha256:ab", "index.docker.io", "x/y", null, "sha256:ab"],
    ["ghcr.io/x/y:v1@sha256:ab", "ghcr.io", "x/y", "v1", "sha256:ab"],
  ])("parses %s", (ref, registry, repository, tag, digest) => {
    expect(parseImageRef(ref)).toEqual({ registry, repository, tag, digest });
  });
});

describe("parsers", () => {
  it("parses a bearer challenge with commas inside quotes", () => {
    expect(parseChallenge('Bearer realm="https://a/token",service="a",scope="repository:x/y:pull,push"')).toEqual({
      scheme: "bearer",
      params: { realm: "https://a/token", service: "a", scope: "repository:x/y:pull,push" },
    });
  });

  it("finds the next link among several", () => {
    expect(nextLink('</a>; rel="prev", </b?last=x&n=1>; rel="next"')).toBe("/b?last=x&n=1");
    expect(nextLink('</a>; rel="prev"')).toBeUndefined();
    expect(nextLink(null)).toBeUndefined();
  });
});

describe("RegistryClient", () => {
  it("answers the bearer challenge and lists tags", async () => {
    const r = hub();
    expect(await client(r).listTags("index.docker.io", "library/app")).toEqual(repo.tags);
    const token = r.calls.find((c) => c.url.startsWith(REALM))!;
    const u = new URL(token.url);
    expect(u.searchParams.get("service")).toBe("svc");
    expect(u.searchParams.get("scope")).toBe("repository:library/app:pull");
    expect(token.authorization).toBeUndefined();
    expect(r.calls.at(-1)!.authorization).toMatch(/^Bearer /);
  });

  it.each([[false], [true]])("follows Link pagination (absolute=%s)", async (absoluteLinks) => {
    const big = { tags: Array.from({ length: 25 }, (_, i) => `1.0.${i}`) };
    const r = hub(host({ repos: { "library/app": big }, pageSize: 10, absoluteLinks }));
    const tags = await client(r).listTags("index.docker.io", "library/app");
    expect(tags).toEqual(big.tags);
    expect(r.count((c) => c.url.includes("/tags/list") && c.authorization !== undefined)).toBe(3);
  });

  it("caches a token until it expires", async () => {
    const r = hub();
    let t = 1_000_000;
    const c = client(r, { now: () => t });
    const tokens = () => r.count((x) => x.url.startsWith(REALM));
    await c.listTags("index.docker.io", "library/app");
    await c.headManifest("index.docker.io", "library/app", "1.0.0");
    expect(tokens()).toBe(1);
    t += 300_000; // past expires_in
    await c.headManifest("index.docker.io", "library/app", "1.0.0");
    expect(tokens()).toBe(2);
  });

  it("assumes 60 seconds when the token response has no expiry", async () => {
    const r = hub();
    r.tokenBody = () => ({ access_token: "abc" });
    let t = 1_000_000;
    const c = client(r, { now: () => t });
    await c.listTags("index.docker.io", "library/app");
    t += 45_000;
    await c.listTags("index.docker.io", "library/app");
    expect(r.count((x) => x.url.startsWith(REALM))).toBe(1);
    t += 10_000;
    await c.listTags("index.docker.io", "library/app");
    expect(r.count((x) => x.url.startsWith(REALM))).toBe(2);
  });

  it("gets a new token when a cached one is refused", async () => {
    const r = hub();
    const c = client(r);
    await c.listTags("index.docker.io", "library/app");
    let refused = false;
    r.intercept = (call) => {
      if (!refused && call.url.includes("/tags/list")) {
        refused = true;
        return new Response("", {
          status: 401,
          headers: { "www-authenticate": `Bearer realm="${REALM}",service="svc",scope="repository:library/app:pull"` },
        });
      }
      return undefined;
    };
    await c.listTags("index.docker.io", "library/app");
    expect(r.count((x) => x.url.startsWith(REALM))).toBe(2);
  });

  it("returns Docker-Content-Digest from a HEAD with every manifest type accepted", async () => {
    const r = hub();
    expect(await client(r).headManifest("index.docker.io", "library/app", "1.0.0")).toBe(digestOf(repo, "1.0.0"));
    const head = r.calls.at(-1)!;
    expect(head.method).toBe("HEAD");
    expect(head.accept).toBe(MANIFEST_ACCEPT);
    for (const t of ["vnd.oci.image.index", "vnd.oci.image.manifest", "manifest.list.v2", "distribution.manifest.v2"]) {
      expect(head.accept).toContain(t);
    }
  });

  it("hashes the body when a registry leaves the digest header off a HEAD", async () => {
    const r = fakeRegistry({ "ghcr.io": { repos: {} } });
    const body = '{"schemaVersion":2}';
    r.intercept = (c) =>
      new Response(c.method === "HEAD" ? null : body, { status: 200 });
    const digest = await client(r).headManifest("ghcr.io", "x/y", "1");
    const { createHash } = await import("node:crypto");
    expect(digest).toBe(`sha256:${createHash("sha256").update(body).digest("hex")}`);
  });

  it("works with no auth at all", async () => {
    const r = fakeRegistry({ "mirror.gcr.io": { repos: { "a/b": { tags: ["1"] } } } });
    expect(await client(r).listTags("mirror.gcr.io", "a/b")).toEqual(["1"]);
    expect(r.calls).toHaveLength(1);
  });

  it("follows a cross-host redirect without carrying the token, and resolves Link against the new host", async () => {
    const r = fakeRegistry({ "cdn.example.test": { repos: { "x/y": { tags: ["1", "2", "3"] } }, pageSize: 2 }, "registry.k8s.io": { repos: {} } });
    const inner = r.fetch;
    r.fetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      const u = new URL(String(input));
      if (u.host === "registry.k8s.io") {
        r.calls.push({ method: "GET", url: u.toString(), authorization: undefined, accept: undefined });
        return new Response(null, { status: 307, headers: { location: `https://cdn.example.test${u.pathname}${u.search}` } });
      }
      return inner(input, init);
    }) as typeof fetch;
    const c = new RegistryClient({ fetch: r.fetch });
    expect(await c.listTags("registry.k8s.io", "x/y")).toEqual(["1", "2", "3"]);
    expect(r.calls.filter((x) => x.url.startsWith("https://cdn.example.test")).every((x) => x.authorization === undefined)).toBe(true);
  });

  it("offers credentials only to a challenge from the image's own registry", async () => {
    const r = fakeRegistry(
      {
        "registry.k8s.io": { repos: {} },
        "cdn.example.test": { repos: { "x/y": { tags: ["1"] } }, realm: REALM },
      },
      ["auth.example.test"],
    );
    r.intercept = (call) => {
      const u = new URL(call.url);
      if (u.host === "registry.k8s.io") return new Response(null, { status: 307, headers: { location: `https://cdn.example.test${u.pathname}${u.search}` } });
      return undefined;
    };
    const c = client(r, { credentials: async () => ({ username: "u", password: "SECRET" }) });
    await c.listTags("registry.k8s.io", "x/y");
    expect(r.calls.find((x) => x.url.startsWith(REALM))!.authorization).toBeUndefined();
  });

  it("sends credentials to the token endpoint as Basic", async () => {
    const r = hub();
    await client(r, { credentials: async () => ({ username: "alice", password: "s3cret" }) }).listTags("index.docker.io", "library/app");
    const auth = r.calls.find((x) => x.url.startsWith(REALM))!.authorization!;
    expect(Buffer.from(auth.replace("Basic ", ""), "base64").toString()).toBe("alice:s3cret");
  });

  it("answers a Basic challenge when credentials exist, and fails clearly when not", async () => {
    const make = () => {
      const r = fakeRegistry({ "reg.example.test": { repos: { "x/y": { tags: ["1"] } } } });
      r.intercept = (c) => (c.authorization?.startsWith("Basic ") ? undefined : new Response("", { status: 401, headers: { "www-authenticate": 'Basic realm="r"' } }));
      return r;
    };
    expect(await client(make(), { credentials: async () => ({ username: "u", password: "p" }) }).listTags("reg.example.test", "x/y")).toEqual(["1"]);
    await expect(client(make()).listTags("reg.example.test", "x/y")).rejects.toBeInstanceOf(RegistryAuthError);
  });

  describe("errors", () => {
    it("types a 429 with its Retry-After", async () => {
      const r = hub();
      r.intercept = (c) => (c.url.includes("/tags/list") ? new Response("", { status: 429, headers: { "retry-after": "120" } }) : undefined);
      const e = await client(r).listTags("index.docker.io", "library/app").catch((x: unknown) => x);
      expect(e).toBeInstanceOf(RegistryRateLimitError);
      expect((e as RegistryRateLimitError).retryAfterMs).toBe(120_000);
    });

    it("recognises TOOMANYREQUESTS outside a 429", async () => {
      const r = hub();
      r.intercept = (c) =>
        c.url.includes("/tags/list") ? new Response('{"errors":[{"code":"TOOMANYREQUESTS","message":"slow down"}]}', { status: 403 }) : undefined;
      await expect(client(r).listTags("index.docker.io", "library/app")).rejects.toBeInstanceOf(RegistryRateLimitError);
    });

    it("types a rate limit from the token endpoint", async () => {
      const r = hub();
      r.intercept = (c) => (c.url.startsWith(REALM) ? new Response("", { status: 429 }) : undefined);
      await expect(client(r).listTags("index.docker.io", "library/app")).rejects.toBeInstanceOf(RegistryRateLimitError);
    });

    it("types a missing repository and a missing tag", async () => {
      const r = hub();
      await expect(client(r).listTags("index.docker.io", "library/nope")).rejects.toBeInstanceOf(RegistryNotFoundError);
      await expect(client(r).headManifest("index.docker.io", "library/app", "9.9.9")).rejects.toBeInstanceOf(RegistryNotFoundError);
    });

    it("types a refused token, and says when no credentials are configured", async () => {
      const r = hub();
      r.intercept = (c) => (c.url.startsWith(REALM) ? new Response('{"errors":[{"code":"DENIED"}]}', { status: 403 }) : undefined);
      const e = await client(r).listTags("index.docker.io", "library/app").catch((x: unknown) => x);
      expect(e).toBeInstanceOf(RegistryAuthError);
      expect((e as Error).message).toMatch(/no credentials are configured/);
    });

    it("types a 401 that persists after a token", async () => {
      const r = hub();
      r.intercept = (c) =>
        c.url.includes("/tags/list") && c.authorization
          ? new Response('{"errors":[{"code":"UNAUTHORIZED"}]}', { status: 401, headers: { "www-authenticate": `Bearer realm="${REALM}",service="svc"` } })
          : undefined;
      await expect(client(r).listTags("index.docker.io", "library/app")).rejects.toBeInstanceOf(RegistryAuthError);
    });

    it("never puts secrets in an error message", async () => {
      const r = hub();
      r.intercept = (c) => (c.url.startsWith(REALM) ? new Response("denied", { status: 401 }) : undefined);
      const e = (await client(r, { credentials: async () => ({ username: "alice", password: "hunter2" }) })
        .listTags("index.docker.io", "library/app")
        .catch((x: unknown) => x)) as Error;
      expect(e).toBeInstanceOf(RegistryAuthError);
      expect(e.message).not.toContain("hunter2");
      expect(e.message).not.toContain(Buffer.from("alice:hunter2").toString("base64"));
    });
  });
});

describe("fileCredentials", () => {
  const dir = () => mkdtempSync(path.join(tmpdir(), "tagamend-creds-"));
  const put = (root: string, host: string, username: string, password: string) => {
    mkdirSync(path.join(root, host), { recursive: true });
    writeFileSync(path.join(root, host, "username"), username);
    writeFileSync(path.join(root, host, "password"), password);
  };

  it("reads a host's files and strips the trailing newline", async () => {
    const d = dir();
    put(d, "ghcr.io", "bot\n", "pat with spaces\n");
    expect(await fileCredentials(d)("ghcr.io")).toEqual({ username: "bot", password: "pat with spaces" });
  });

  it("is anonymous when the directory, the host or a file is missing", async () => {
    expect(await fileCredentials("/nonexistent/creds")("ghcr.io")).toBeUndefined();
    const d = dir();
    expect(await fileCredentials(d)("ghcr.io")).toBeUndefined();
    mkdirSync(path.join(d, "quay.io"));
    writeFileSync(path.join(d, "quay.io", "username"), "only-user");
    expect(await fileCredentials(d)("quay.io")).toBeUndefined();
  });

  it("finds Docker Hub under the name trivy reports", async () => {
    const d = dir();
    put(d, "index.docker.io", "u", "p");
    expect(await fileCredentials(d)("docker.io")).toEqual({ username: "u", password: "p" });
    expect(await fileCredentials(d)("index.docker.io")).toEqual({ username: "u", password: "p" });
  });

  it("refuses a host name that would escape the directory", async () => {
    const d = dir();
    put(path.dirname(d), "escape", "u", "p");
    expect(await fileCredentials(d)("../escape")).toBeUndefined();
  });
});
