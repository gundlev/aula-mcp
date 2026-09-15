/**
 * Process-wide token refresh coordinator.
 *
 * `withFreshTokens()` is correct for one caller; the MCP server has many.
 * Every HTTP or SSE session builds its own AulaContext, and inside one
 * context several tool calls can race. Before this file each of them could
 * observe "token expired" at the same instant and issue its own refresh
 * request with the same soon-to-be-invalid refresh token.
 *
 * A TokenRefresher is shared by every consumer of the same token store
 * (identified by its file path / keychain path — see `storeIdentity`) and
 * guarantees:
 *   - at most one in-flight load/refresh per store per process; concurrent
 *     callers await the same promise,
 *   - a failed refresh is not cached — the next caller retries,
 *   - the store is re-read at least every `recheckIntervalMs` even while the
 *     cached tokens look valid, so an out-of-band `aula logout` (or a fresh
 *     login on a platform without file watching) is noticed without waiting
 *     for the access token to expire.
 *
 * Cross-process coordination (server + CLI, or two servers) is handled one
 * layer down by the lock in `withFreshTokens`.
 */

import type { AulaOAuthConfig } from './aula-oauth.ts';
import { isTokenExpired } from './aula-oauth.ts';
import type { AulaHttpClient } from './http.ts';
import type { Logger } from './logger.ts';
import { silentLogger } from './logger.ts';
import { type StoredTokenRecord, type TokenStore, withFreshTokens } from './token-store.ts';

export interface TokenRefresherOptions {
  store: TokenStore;
  http: AulaHttpClient;
  oauth?: AulaOAuthConfig;
  /** Seconds before expiry that count as "expired". Default 60. */
  refreshBufferSeconds?: number;
  /** Re-read the store at most this often while cached tokens are valid.
   *  Default 30 s; `0` re-reads on every call (tests). */
  recheckIntervalMs?: number;
  logger?: Logger;
}

export class TokenRefresher {
  private readonly store: TokenStore;
  private readonly http: AulaHttpClient;
  private readonly oauth: AulaOAuthConfig | undefined;
  private readonly refreshBufferSeconds: number;
  private readonly recheckIntervalMs: number;
  private readonly logger: Logger;

  private inFlight: Promise<StoredTokenRecord> | undefined;
  private cached: StoredTokenRecord | undefined;
  private cachedAt = 0;
  private lastError: { at: number; message: string } | undefined;

  constructor(options: TokenRefresherOptions) {
    this.store = options.store;
    this.http = options.http;
    this.oauth = options.oauth;
    this.refreshBufferSeconds = options.refreshBufferSeconds ?? 60;
    this.recheckIntervalMs = options.recheckIntervalMs ?? 30_000;
    this.logger = options.logger ?? silentLogger;
  }

  /**
   * A record whose access token is valid for at least the refresh buffer.
   * Concurrent callers share one load; a refresh happens at most once per
   * expiry regardless of how many sessions notice it.
   */
  async getFresh(): Promise<StoredTokenRecord> {
    if (this.inFlight) return this.inFlight;
    if (
      this.cached &&
      !isTokenExpired(this.cached.tokens, this.refreshBufferSeconds) &&
      Date.now() - this.cachedAt < this.recheckIntervalMs
    ) {
      return this.cached;
    }
    const load = (async () => {
      try {
        const record = await withFreshTokens({
          store: this.store,
          http: this.http,
          ...(this.oauth ? { oauth: this.oauth } : {}),
          refreshBufferSeconds: this.refreshBufferSeconds,
          logger: this.logger,
        });
        this.cached = record;
        this.cachedAt = Date.now();
        this.lastError = undefined;
        return record;
      } catch (err) {
        // Drop the cache so a caller never sees tokens the store no longer
        // holds, and remember the failure for readiness reporting.
        this.cached = undefined;
        this.lastError = { at: Date.now(), message: (err as Error).message };
        throw err;
      } finally {
        this.inFlight = undefined;
      }
    })();
    this.inFlight = load;
    return load;
  }

  /** Force the next `getFresh()` to re-read the store. */
  invalidate(): void {
    this.cached = undefined;
    this.cachedAt = 0;
  }

  /** Last record handed out, if any. Does not touch the store. */
  get current(): StoredTokenRecord | undefined {
    return this.cached;
  }

  /** Most recent load/refresh failure, cleared by the next success. */
  get recentError(): { at: number; message: string } | undefined {
    return this.lastError;
  }
}

// --------------------------------------------------------------------------
// Registry: one refresher per token store per process
// --------------------------------------------------------------------------

const byIdentity = new Map<string, TokenRefresher>();
const byObject = new WeakMap<TokenStore, TokenRefresher>();

/**
 * Stable identity for stores that address the same credentials even when
 * constructed separately (every MCP session builds its own store object).
 */
export function storeIdentity(store: TokenStore): string | undefined {
  const identity = (store as { identity?: unknown }).identity;
  if (typeof identity === 'string' && identity.length > 0) return identity;
  const filePath = (store as { filePath?: unknown }).filePath;
  if (typeof filePath === 'string' && filePath.length > 0) return `file:${filePath}`;
  return undefined;
}

/**
 * The shared refresher for `options.store`, creating it on first use. The
 * http client / logger of the first caller are kept for the lifetime of the
 * process; all callers build them identically in practice.
 */
export function getTokenRefresher(options: TokenRefresherOptions): TokenRefresher {
  const id = storeIdentity(options.store);
  if (id) {
    const existing = byIdentity.get(id);
    if (existing) return existing;
    const created = new TokenRefresher(options);
    byIdentity.set(id, created);
    return created;
  }
  const existing = byObject.get(options.store);
  if (existing) return existing;
  const created = new TokenRefresher(options);
  byObject.set(options.store, created);
  return created;
}

/** Tests only: forget every shared refresher. */
export function resetTokenRefreshers(): void {
  byIdentity.clear();
}
