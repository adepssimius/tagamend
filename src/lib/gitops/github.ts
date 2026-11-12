/**
 * The few GitHub REST calls a GitOps PR needs. Files are read from one
 * tarball of the base branch and the change is committed through the Git Data
 * API, so a PR costs a handful of requests whatever the repo's size.
 */
export interface GitHub {
  /** The commit SHA the branch points at. */
  branchSha(branch: string): Promise<string>;
  /** The gzipped tarball of a commit. */
  tarball(sha: string): Promise<Uint8Array>;
  /** Commits `files` on top of `baseSha` and points a new branch at it. */
  commitToNewBranch(opts: { baseSha: string; branch: string; message: string; files: Map<string, string> }): Promise<string>;
  /** An open PR from `branch`, if one exists. */
  findOpenPr(branch: string): Promise<{ number: number; url: string } | null>;
  openPr(opts: { head: string; base: string; title: string; body: string }): Promise<{ number: number; url: string }>;
  branchExists(branch: string): Promise<boolean>;
  /** Where a PR stands now. */
  prState(number: number): Promise<"open" | "draft" | "merged" | "closed">;
}

export class GitHubError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export function gitHubClient(repo: string, token: string, fetchImpl: typeof fetch = fetch): GitHub {
  const [owner] = repo.split("/");
  const api = async (path: string, init: RequestInit = {}, accept = "application/vnd.github+json") => {
    const res = await fetchImpl(`https://api.github.com/repos/${repo}${path}`, {
      ...init,
      headers: {
        Accept: accept,
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "tagamend",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
      },
      redirect: "follow",
    });
    if (!res.ok) {
      let detail = "";
      try {
        detail = ((await res.json()) as { message?: string }).message ?? "";
      } catch {
        /* not JSON */
      }
      throw new GitHubError(`GitHub ${init.method ?? "GET"} ${path}: ${res.status} ${detail}`.trim(), res.status);
    }
    return res;
  };
  const json = async <T>(path: string, init?: RequestInit) => (await (await api(path, init)).json()) as T;
  const post = <T>(path: string, body: unknown) => json<T>(path, { method: "POST", body: JSON.stringify(body) });

  return {
    async branchSha(branch) {
      return (await json<{ object: { sha: string } }>(`/git/ref/heads/${encodeURIComponent(branch)}`)).object.sha;
    },
    async tarball(sha) {
      return new Uint8Array(await (await api(`/tarball/${sha}`)).arrayBuffer());
    },
    async commitToNewBranch({ baseSha, branch, message, files }) {
      const base = await json<{ tree: { sha: string } }>(`/git/commits/${baseSha}`);
      const tree = await post<{ sha: string }>("/git/trees", {
        base_tree: base.tree.sha,
        tree: [...files].map(([path, content]) => ({ path, mode: "100644", type: "blob", content })),
      });
      const commit = await post<{ sha: string }>("/git/commits", { message, tree: tree.sha, parents: [baseSha] });
      await post("/git/refs", { ref: `refs/heads/${branch}`, sha: commit.sha });
      return commit.sha;
    },
    async findOpenPr(branch) {
      const prs = await json<{ number: number; html_url: string }[]>(
        `/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}`,
      );
      return prs[0] ? { number: prs[0].number, url: prs[0].html_url } : null;
    },
    async openPr({ head, base, title, body }) {
      const pr = await post<{ number: number; html_url: string }>("/pulls", { head, base, title, body });
      return { number: pr.number, url: pr.html_url };
    },
    async prState(number) {
      const pr = await json<{ state: "open" | "closed"; merged_at: string | null; draft?: boolean }>(`/pulls/${number}`);
      if (pr.merged_at) return "merged";
      if (pr.state === "closed") return "closed";
      return pr.draft ? "draft" : "open";
    },
    async branchExists(branch) {
      try {
        await api(`/git/ref/heads/${encodeURIComponent(branch)}`);
        return true;
      } catch (e) {
        if (e instanceof GitHubError && e.status === 404) return false;
        throw e;
      }
    },
  };
}
