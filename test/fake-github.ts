import type { GitHub } from "@/lib/gitops/github";
import { repoTarball } from "./tar-writer";

/** A GitHub that serves a synthetic repo tarball and records commits and PRs. */
export class FakeGitHub implements GitHub {
  commits: { branch: string; message: string; files: Map<string, string> }[] = [];
  prs: { head: string; base: string; title: string; body: string }[] = [];
  existingBranches = new Set<string>();
  constructor(private files: Record<string, string>) {}
  async branchSha() {
    return "base-sha";
  }
  async tarball() {
    return repoTarball(this.files);
  }
  async commitToNewBranch(o: { baseSha: string; branch: string; message: string; files: Map<string, string> }) {
    this.commits.push(o);
    this.existingBranches.add(o.branch);
    return "new-sha";
  }
  async findOpenPr() {
    return null;
  }
  async openPr(o: { head: string; base: string; title: string; body: string }) {
    this.prs.push(o);
    return { number: 7, url: "https://github.com/o/r/pull/7" };
  }
  async branchExists(b: string) {
    return this.existingBranches.has(b);
  }
  states = new Map<number, "open" | "draft" | "merged" | "closed">();
  stateCalls = 0;
  async prState(n: number) {
    this.stateCalls++;
    return this.states.get(n) ?? "open";
  }
}
