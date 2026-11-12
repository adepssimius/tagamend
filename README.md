# tagamend

Shows the CVEs in the images running on a Kubernetes cluster, finds newer tags
of those images, and scans a chosen tag on demand to show which CVEs it
resolves.

It reads trivy-operator's `VulnerabilityReport`s, so trivy-operator must be
installed. Candidate scans use trivy-operator's built-in Trivy server.

## Processes

One image, two processes:

- **web** (`next start`): the UI. Reads the database and queues scans. Never
  calls a registry or the Kubernetes API in a request.
- **worker** (`node dist/worker.js`): runs migrations, then the report sync,
  tag discovery, and scan queue loops. Run exactly one.

## Development

```bash
cp .env.example .env.local      # then edit
npm install
npm run migrate
npm run dev                     # web on :3000
npm run dev:worker              # worker, in a second terminal
```

`AUTH_DEV_USER=<name>` skips OIDC outside production. `npm run seed` loads
fixture data so the UI has something to show without a cluster.

For report sync against a real cluster, set `KUBECONFIG`. For scans, set
`SCANNER=local` with `trivy` on your PATH, and port-forward the Trivy server:

```bash
kubectl -n trivy-system port-forward svc/trivy-service 4954:4954
```

## Database

`DATABASE_URL` picks the dialect: `file:./dev.db` for SQLite, `postgres://...`
for Postgres. One set of Kysely queries runs on both. Timestamps are ISO-8601
text and booleans are integers on both, so query results have the same types.

Tests run every database test on SQLite, and on Postgres too when
`TEST_POSTGRES_URL` is set (CI sets it).

## Registry credentials

The worker reads credentials for tag listing from `REGISTRY_CREDENTIALS_DIR`,
one directory per registry host, named as trivy reports the host:

```
/secrets/registries/ghcr.io/username
/secrets/registries/ghcr.io/password
/secrets/registries/index.docker.io/username
/secrets/registries/index.docker.io/password
```

In Kubernetes, mount each registry's Secret there with `items` mapping its keys
to `username` and `password`. A host with no directory is accessed
anonymously.

Scan Jobs cannot read the worker's files, so they take credentials from
Secrets in `SCAN_NAMESPACE`, named by `SCAN_REGISTRY_SECRETS`
(`host=secret/usernameKey/passwordKey;...`).

## GitOps pull requests

With `GITOPS_REPO` set, each scanned candidate on an image page gets an
**Open PR** button. The worker downloads the base branch once as a tarball,
finds the image's references, commits the tag change to a new branch, and
opens a PR whose body carries the candidate scan's diff.

It moves references in three forms: `image: <ref>` lines, Helm values with
`repository:` and `tag:` keys, and Kustomize `images:` entries with `newTag:`.
It moves only tags that are running now and have the same shape as the
candidate, and leaves alone lines Flux image automation manages and digest
pins, listing them in the PR. An image that the repo does not name, such as
one from a Helm chart's defaults, fails with that reason instead of opening an
empty PR.

The worker needs `GITHUB_TOKEN`: a fine-grained PAT limited to that repository,
with Contents and Pull requests read and write. The web process never sees it.

The web process can take `GITHUB_READ_TOKEN`, a separate fine-grained PAT with
only Pull requests read on that repository. With it, pages that show an open PR
ask GitHub for its state as they load (cached 30 seconds, 3-second timeout), so
a merge shows on the next reload. Without it, PRs show as open.

## Configuration

See `src/lib/config.ts` for every variable and its default, and `.env.example`.

## License

MIT. See [LICENSE](LICENSE).
