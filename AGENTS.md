# AGENTS.md

- `npm run typecheck` and `npm test` must pass. Database tests loop over
  `testDatabases()` in `test/helpers.ts` so they run on SQLite and Postgres.
- Queries must work on both dialects: no arrays, no `jsonb`, JSON stored as
  text, timestamps as ISO strings from `now()`, booleans as 0/1. Use
  `onConflict(...)` for upserts and `.returning(...)` for ids; both dialects
  support them.
- New migrations go in `src/lib/db/migrations/` and are registered in
  `migrations/index.ts`. Never edit a migration that has shipped.
- Write vulnerability data only through `storeDigest` in `src/lib/db/store.ts`.
  Both the report sync and the scan runner normalise into `Finding` first.
- The web process never calls a registry or the Kubernetes API.
- Every page and server action calls `requireUser()` first.
- Logs are JSON lines via `src/lib/log.ts`.
