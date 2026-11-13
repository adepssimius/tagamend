import { fluxScope } from "../queries/common";
import type { DB } from "../db";
import { errorMessage } from "../log";
import { RegistryClient } from "../registry/client";
import { type CredentialLookup, fileCredentials } from "../registry/credentials";
import { RegistryError, RegistryNotFoundError, RegistryRateLimitError } from "../registry/errors";
import { apiHost } from "../registry/hosts";
import { chooseCandidates, parseTag } from "../registry/tag-shape";
import type { WorkerContext } from "../worker-context";

/** At least this many images per tick, so a first pass does not take the whole interval. */
const MIN_IMAGES_PER_TICK = 3;
const TICK_MS = 60_000;
/** How long to leave a registry alone after a 429 that has no Retry-After. */
const DEFAULT_BACKOFF_MS = 15 * 60_000;

/** API host to the time (ms) it may be called again. Kept between ticks; the worker is one process. */
const registryBackoff = new Map<string, number>();

export interface TagSyncOptions {
  fetch?: typeof fetch;
  credentials?: CredentialLookup;
  backoff?: Map<string, number>;
  now?: () => number;
  /** Images per tick; computed from the interval when not given. */
  batch?: number;
}

/**
 * Called every minute. Picks the images in use whose tags are due, a few per
 * tick so a full pass spreads over TAG_SYNC_INTERVAL, lists their tags, and
 * records the candidates in `tags`.
 */
export async function syncTags(ctx: WorkerContext): Promise<Record<string, unknown>> {
  return runTagSync(ctx);
}

interface DueImage {
  id: number;
  registry: string;
  repository: string;
  last_tag_sync_at: string | null;
}

interface Row {
  tag: string;
  digest: string | null;
  isCandidate: boolean;
  reasons: string[];
}

export async function runTagSync(ctx: WorkerContext, opts: TagSyncOptions = {}): Promise<Record<string, unknown>> {
  const nowMs = opts.now ?? Date.now;
  const backoff = opts.backoff ?? registryBackoff;
  const client = new RegistryClient({
    fetch: opts.fetch,
    credentials: opts.credentials ?? fileCredentials(ctx.config.REGISTRY_CREDENTIALS_DIR),
    signal: ctx.signal,
    now: nowMs,
  });

  // Images only out-of-scope workloads run are not checked: no registry calls for them.
  const fluxOnly = await fluxScope(ctx.db);
  const inUse = await ctx.db
    .selectFrom("images")
    .select(["images.id", "images.registry", "images.repository", "images.last_tag_sync_at"])
    .where((eb) =>
      eb.exists(
        eb
          .selectFrom("workloads")
          .select("workloads.id")
          .whereRef("workloads.image_id", "=", "images.id")
          .where("workloads.gone_at", "is", null)
          .where((w) =>
            fluxOnly ? w.or([w("workloads.managed_by", "is", null), w("workloads.managed_by", "!=", "none")]) : w.lit(true),
          ),
      ),
    )
    .execute();

  const cutoff = new Date(nowMs() - ctx.config.TAG_SYNC_INTERVAL).toISOString();
  const due = inUse
    .filter((i) => i.last_tag_sync_at === null || i.last_tag_sync_at < cutoff)
    .sort(
      (a, b) =>
        (a.last_tag_sync_at ?? "").localeCompare(b.last_tag_sync_at ?? "") || a.id - b.id,
    );
  const batch =
    opts.batch ?? Math.max(MIN_IMAGES_PER_TICK, Math.ceil((inUse.length * TICK_MS) / ctx.config.TAG_SYNC_INTERVAL));

  const counts = { due: due.length, synced: 0, candidates: 0, pinned: 0, errors: 0, skipped: 0 };
  const rateLimited = new Set<string>();
  let attempted = 0;

  for (const image of due) {
    if (ctx.signal.aborted || attempted >= batch) break;
    const host = apiHost(image.registry);
    const until = backoff.get(host);
    if (rateLimited.has(host) || (until !== undefined && until > nowMs())) {
      counts.skipped++;
      continue;
    }
    if (until !== undefined) backoff.delete(host);
    attempted++;

    try {
      const out = await syncImage(ctx.db, client, image, new Date(nowMs()).toISOString());
      counts.synced++;
      counts.candidates += out.candidates;
      if (out.pinned) counts.pinned++;
    } catch (e) {
      if (ctx.signal.aborted) break;
      const message = errorMessage(e);
      if (e instanceof RegistryRateLimitError) {
        // Left due, so it is the first thing tried once the backoff ends.
        rateLimited.add(host);
        backoff.set(host, nowMs() + (e.retryAfterMs ?? DEFAULT_BACKOFF_MS));
        await ctx.db.updateTable("images").set({ tag_sync_error: message }).where("id", "=", image.id).execute();
        ctx.log.warn("tag sync rate limited", { registry: image.registry, repository: image.repository, error: message });
      } else {
        // A broken image waits for the next interval rather than retrying every minute.
        counts.errors++;
        await ctx.db
          .updateTable("images")
          .set({ tag_sync_error: message, last_tag_sync_at: new Date(nowMs()).toISOString() })
          .where("id", "=", image.id)
          .execute();
        ctx.log.warn("tag sync failed", { registry: image.registry, repository: image.repository, error: message });
      }
    }
  }

  return { ...counts, rateLimited: [...rateLimited] };
}

async function syncImage(
  db: DB,
  client: RegistryClient,
  image: DueImage,
  at: string,
): Promise<{ candidates: number; pinned: boolean }> {
  // Running tags of out-of-scope workloads do not shape the candidates.
  const scoped = await fluxScope(db);
  const workloads = await db
    .selectFrom("workloads")
    .leftJoin("image_digests", "image_digests.id", "workloads.digest_id")
    .select(["workloads.tag", "image_digests.digest"])
    .where("workloads.image_id", "=", image.id)
    .where("workloads.gone_at", "is", null)
    .where((w) =>
      scoped ? w.or([w("workloads.managed_by", "is", null), w("workloads.managed_by", "!=", "none")]) : w.lit(true),
    )
    .execute();

  /** Running tag to the digests its workloads actually run. */
  const running = new Map<string, Set<string>>();
  for (const w of workloads) {
    if (w.tag === null) continue;
    const digests = running.get(w.tag) ?? new Set<string>();
    if (w.digest) digests.add(w.digest);
    running.set(w.tag, digests);
  }
  const pinned = running.size === 0;

  const rows = new Map<string, Row>();
  const note = (tag: string, reason: string, isCandidate: boolean, digest: string | null = null) => {
    const row = rows.get(tag) ?? { tag, digest: null, isCandidate: false, reasons: [] };
    row.reasons.push(reason);
    row.isCandidate ||= isCandidate;
    row.digest ??= digest;
    rows.set(tag, row);
  };

  // Listing is the expensive call, and a floating tag does not need it.
  const ordered = [...running.keys()].sort().filter((tag) => parseTag(tag).kind === "version");
  if (ordered.length > 0) {
    const allTags = await client.listTags(image.registry, image.repository);
    for (const tag of ordered) {
      const choice = chooseCandidates(tag, allTags);
      if (choice.mode === "version") for (const c of choice.candidates) note(c.tag, c.reason, true);
    }
  }

  for (const [tag, digests] of running) {
    let current: string;
    try {
      current = await client.headManifest(image.registry, image.repository, tag);
    } catch (e) {
      // The tag was deleted upstream. Nothing to compare; its workloads keep running.
      if (e instanceof RegistryNotFoundError) continue;
      throw e;
    }
    const behind = [...digests].filter((d) => d !== current);
    if (behind.length > 0) {
      note(tag, `${tag} now points to ${short(current)}; running ${behind.map(short).join(", ")}`, true, current);
    } else if (digests.size === 0 && parseTag(tag).kind === "floating") {
      note(tag, `${tag} points to ${short(current)}; the running digest is not known, so drift cannot be checked`, false, current);
    }
  }

  for (const row of rows.values()) {
    if (row.digest !== null) continue;
    try {
      row.digest = await client.headManifest(image.registry, image.repository, row.tag);
    } catch (e) {
      // Anything else (a 404 on a listed tag, say) leaves this one tag without a digest.
      if (e instanceof RegistryRateLimitError || !(e instanceof RegistryError)) throw e;
      row.reasons.push(`digest not available: ${errorMessage(e)}`);
    }
  }

  await db.transaction().execute(async (trx) => {
    for (const row of rows.values()) {
      const values = {
        digest: row.digest,
        is_candidate: row.isCandidate ? 1 : 0,
        reason: row.reasons.join("; "),
      };
      await trx
        .insertInto("tags")
        .values({ image_id: image.id, tag: row.tag, first_seen_at: at, ...values })
        .onConflict((oc) => oc.columns(["image_id", "tag"]).doUpdateSet(values))
        .execute();
    }
    let stale = trx.deleteFrom("tags").where("image_id", "=", image.id);
    if (rows.size > 0) stale = stale.where("tag", "not in", [...rows.keys()]);
    await stale.execute();
    await trx.updateTable("images").set({ last_tag_sync_at: at, tag_sync_error: null }).where("id", "=", image.id).execute();
  });

  return { candidates: [...rows.values()].filter((r) => r.isCandidate).length, pinned };
}

function short(digest: string): string {
  const hex = digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
  return `sha256:${hex.slice(0, 12)}`;
}
