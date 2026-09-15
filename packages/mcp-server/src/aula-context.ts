/**
 * Lazy AulaClient + WidgetTokenManager that the MCP tools share. Tokens are
 * loaded on first use and refreshed transparently.
 *
 * The MCP server is deliberately stateless across restarts: it always reads
 * the same EncryptedFileTokenStore that the CLI writes to. This means
 * `aula login` from the terminal "just works" with any running server.
 */

import { type FSWatcher, watch } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  AulaHttpClient,
  EncryptedFileTokenStore,
  getTokenRefresher,
  isTokenExpired,
  KeychainTokenStore,
  type Logger,
  type StoredTokenRecord,
  silentLogger,
  type TokenRefresher,
  type TokenStore,
} from '@aula-mcp/aula-auth';
import {
  AulaClient,
  EasyIqClient,
  EasyIqLektierClient,
  EasyIqSkoleportalClient,
  MeebookClient,
  MinUddannelseClient,
  SystematicClient,
  WidgetTokenManager,
} from '@aula-mcp/aula-client';

export interface AulaContextOptions {
  store?: TokenStore;
  logger?: Logger;
  /** HTTP client for Aula and the token endpoint (tests inject a fake). */
  http?: AulaHttpClient;
  /** Seconds before expiry at which tokens count as expired. Default 60. */
  refreshBufferSeconds?: number;
  /** How often the shared refresher re-reads the store while its cached
   *  tokens still look valid. Default 30 s; `0` re-reads on every call. */
  recheckIntervalMs?: number;
  /** Override the process-wide refresher (tests). */
  refresher?: TokenRefresher;
}

/** What `/readyz` reports. Coarse on purpose: no usernames, no expiry times. */
export interface AuthReadiness {
  ready: boolean;
  reason?: 'no_tokens' | 'refresh_failing' | 'store_error';
}

/** A refresh failure this recent, with expired tokens, means "not ready". */
const REFRESH_FAILURE_GRACE_MS = 10 * 60 * 1000;

export class AulaContext {
  private readonly store: TokenStore;
  private readonly logger: Logger;
  private readonly http: AulaHttpClient;
  private readonly refreshBufferSeconds: number;
  /**
   * Shared with every other context on the same token store (see
   * `getTokenRefresher`): one in-flight refresh per store per process, so N
   * MCP sessions noticing expiry at once produce one refresh request, not N.
   */
  private readonly refresher: TokenRefresher;
  // Fields below are declared as `T | undefined` (not just `T?`) so we can
  // explicitly assign `undefined` to invalidate the cache (the strict
  // `exactOptionalPropertyTypes` flag forbids `field = undefined` on `T?`).
  private client: AulaClient | undefined;
  /** In-flight `getClient()` so concurrent callers in this context share it. */
  private clientPromise: Promise<AulaClient> | undefined;
  private widgetManager: WidgetTokenManager | undefined;
  private cachedRecord: StoredTokenRecord | undefined;
  /** Guardian user-id from getProfileContext. Used as the
   *  sessionId/sessionUUID/sessionuuid parameter by the third-party
   *  integrations. Stored as string — Aula returns either a numeric id
   *  or an opaque alphanumeric token; we treat it as opaque to match
   *  upstream Python's `str(child["userId"])` handling. */
  private cachedGuardianUserId: string | undefined;
  private tokenFileWatcher: FSWatcher | undefined;
  private tokenFileChangeDebounce: NodeJS.Timeout | undefined;
  private disposed = false;

  constructor(options: AulaContextOptions = {}) {
    this.store = options.store ?? defaultStore();
    this.logger = options.logger ?? silentLogger;
    this.http = options.http ?? new AulaHttpClient({ logger: this.logger });
    this.refreshBufferSeconds = options.refreshBufferSeconds ?? 60;
    this.refresher =
      options.refresher ??
      getTokenRefresher({
        store: this.store,
        http: this.http,
        logger: this.logger,
        refreshBufferSeconds: this.refreshBufferSeconds,
        ...(options.recheckIntervalMs !== undefined
          ? { recheckIntervalMs: options.recheckIntervalMs }
          : {}),
      });
    this.watchTokenFile();
  }

  /**
   * If the underlying store is file-backed, watch its path and invalidate the
   * cached client whenever the file changes (e.g. an out-of-band `aula login`
   * or `aula refresh-stepup` rotates tokens). Without this, the cached client
   * keeps serving 401/403 against the rotated session until its access token
   * naturally expires (~60min).
   *
   * Best-effort: errors here are non-fatal. The original token-expiry
   * invalidation in `getClient()` is still the backstop.
   *
   * Duck-typed (`'filePath' in store && typeof string`) rather than
   * `instanceof EncryptedFileTokenStore`: Bun's `--compile` bundler can
   * produce two copies of the same class when the package is imported via
   * different specifiers across the bundled graph, breaking `instanceof`
   * silently — the watcher then never gets attached and stale tokens linger.
   */
  private watchTokenFile(): void {
    const filePath = (this.store as { filePath?: unknown }).filePath;
    if (typeof filePath !== 'string' || filePath.length === 0) return;
    const path = filePath;
    try {
      this.tokenFileWatcher = watch(path, { persistent: false }, (eventType) => {
        // fs.watch tends to fire multiple events per write (the writer does
        // write + close + chmod). Debounce so we only invalidate once.
        if (this.tokenFileChangeDebounce) clearTimeout(this.tokenFileChangeDebounce);
        this.tokenFileChangeDebounce = setTimeout(() => {
          this.tokenFileChangeDebounce = undefined;
          this.logger.info('aula-context.token_file_changed_invalidating', {
            path,
            eventType,
          });
          this.invalidate();
        }, 250);
      });
      this.tokenFileWatcher.on('error', (err) => {
        this.logger.warn('aula-context.token_file_watch_error', {
          path,
          error: err instanceof Error ? err.message : String(err),
        });
      });
    } catch (err) {
      this.logger.warn('aula-context.token_file_watch_setup_failed', {
        path,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Release everything this context holds: the token-file watcher and the
   * cached client. Called by the HTTP server when the owning MCP session
   * closes (audit finding 7 — watchers used to accumulate per session).
   * The shared refresher is process-wide and is deliberately left alone.
   */
  dispose(): void {
    this.disposed = true;
    if (this.tokenFileChangeDebounce) {
      clearTimeout(this.tokenFileChangeDebounce);
      this.tokenFileChangeDebounce = undefined;
    }
    this.tokenFileWatcher?.close();
    this.tokenFileWatcher = undefined;
    this.client = undefined;
    this.clientPromise = undefined;
    this.widgetManager = undefined;
    this.cachedRecord = undefined;
  }

  /**
   * Get the AulaClient, refreshing tokens if expired.
   *
   * Every call goes through the shared refresher, which answers from its
   * cache while the access token is valid (a synchronous check) and
   * otherwise performs — or joins — the single in-flight refresh for this
   * token store. Within one context concurrent callers additionally share
   * `clientPromise`, so N parallel tool calls on an expired token produce
   * one refresh request, not N (the race the audit reproduced).
   *
   * When the refresher hands back different tokens than the client was
   * built with (a refresh here, or an out-of-band `aula login`), the client
   * and its widget-token manager are rebuilt so nothing keeps using the old
   * session.
   */
  async getClient(): Promise<AulaClient> {
    if (this.disposed) throw new Error('AulaContext has been disposed');
    if (this.clientPromise) return this.clientPromise;
    const load = this.loadClient().finally(() => {
      // Only the in-flight window is shared; the next call re-checks token
      // validity through the refresher's cache.
      if (this.clientPromise === load) this.clientPromise = undefined;
    });
    this.clientPromise = load;
    return load;
  }

  /**
   * Whether this server can currently act on Aula, for `/readyz`.
   *
   * Reads the store directly so a missing or unreadable token file is
   * reported even before any tool call. With an expired access token the
   * answer depends on a refresh working; that refresh is attempted through
   * the shared refresher (so it is shared with tool calls, and keeps the
   * refresh-token chain alive on an otherwise idle server) but at most once
   * per grace window while it keeps failing.
   */
  async readiness(): Promise<AuthReadiness> {
    let record: StoredTokenRecord | null;
    try {
      record = await this.store.load();
    } catch (err) {
      this.logger.warn('aula-context.readiness.store_error', {
        error: err instanceof Error ? err.message : String(err),
      });
      return { ready: false, reason: 'store_error' };
    }
    if (!record) return { ready: false, reason: 'no_tokens' };
    if (!isTokenExpired(record.tokens, this.refreshBufferSeconds)) return { ready: true };

    const recent = this.refresher.recentError;
    if (recent && Date.now() - recent.at < REFRESH_FAILURE_GRACE_MS) {
      return { ready: false, reason: 'refresh_failing' };
    }
    try {
      await this.refresher.getFresh();
      return { ready: true };
    } catch {
      return { ready: false, reason: 'refresh_failing' };
    }
  }

  /** Drop all cached state. Useful for tests; also called when an upstream
   *  401/403 indicates the server's view of our tokens is wrong. The shared
   *  refresher is told to re-read the store on its next call as well. */
  invalidate(): void {
    this.client = undefined;
    this.clientPromise = undefined;
    this.widgetManager = undefined;
    this.cachedRecord = undefined;
    this.cachedGuardianUserId = undefined;
    this.refresher.invalidate();
  }

  /**
   * Guardian user-id (from `profiles.getProfileContext.data.userId`).
   * Required as the `sessionId` / `sessionUUID` / `sessionuuid` parameter for
   * EasyIQ, Min Uddannelse, and Meebook. Cached after the first call.
   *
   * Per Python `client.py:670/757` — the integration calls fail without it.
   * Aula returns this as either a number or an opaque alphanumeric token;
   * we coerce to string and pass through verbatim.
   */
  async getGuardianUserId(): Promise<string> {
    if (this.cachedGuardianUserId !== undefined) return this.cachedGuardianUserId;
    const client = await this.getClient();
    const ctx = await client.getProfileContext('guardian');
    if (ctx.userId == null || ctx.userId === '') {
      throw new Error('profiles.getProfileContext returned no userId');
    }
    this.cachedGuardianUserId = String(ctx.userId);
    return this.cachedGuardianUserId;
  }

  /**
   * Widget-token manager bound to the current client. `loadClient()` drops
   * it whenever the client is rebuilt, so widget tokens minted under a
   * previous Aula session are never reused after a token rotation.
   */
  async getWidgetManager(): Promise<WidgetTokenManager> {
    const client = await this.getClient();
    this.widgetManager ??= new WidgetTokenManager({ client });
    return this.widgetManager;
  }

  async getEasyIq(): Promise<EasyIqClient> {
    return new EasyIqClient({ http: this.http, widgets: await this.getWidgetManager() });
  }

  async getEasyIqSkoleportal(): Promise<EasyIqSkoleportalClient> {
    return new EasyIqSkoleportalClient({
      http: this.http,
      widgets: await this.getWidgetManager(),
    });
  }

  async getEasyIqLektier(): Promise<EasyIqLektierClient> {
    return new EasyIqLektierClient({
      http: this.http,
      widgets: await this.getWidgetManager(),
    });
  }

  async getMeebook(): Promise<MeebookClient> {
    return new MeebookClient({ http: this.http, widgets: await this.getWidgetManager() });
  }

  async getMinUddannelse(): Promise<MinUddannelseClient> {
    return new MinUddannelseClient({ http: this.http, widgets: await this.getWidgetManager() });
  }

  async getSystematic(): Promise<SystematicClient> {
    return new SystematicClient({ http: this.http, widgets: await this.getWidgetManager() });
  }

  /** The currently-loaded record (after first getClient()). */
  get record(): StoredTokenRecord | undefined {
    return this.cachedRecord;
  }

  private async loadClient(): Promise<AulaClient> {
    // Plain refresh_token grant (performed inside the shared refresher). The
    // scaarup/aula HA integration has proven empirically that Aula's OAuth
    // server preserves the `aula-sensitive` scope through refresh_token
    // grants — HA reads sensitive endpoints (messaging.getMessagesForThread)
    // for months from a single MitID login using nothing but
    // `grant_type=refresh_token` against simplesaml/.../token.php.
    // Earlier suspicion that step-up assurance was bound to the
    // broker session at unilogin.dk was a misdiagnosis — the 403s we
    // were seeing were the v22→v23 apiVersion deprecation (fixed in
    // 60c4246), not step-up loss. The `aula refresh-stepup` CLI command
    // is kept as a manual recovery tool when the refresh_token chain
    // breaks (e.g. after a long downtime), but the MCP child no longer
    // invokes it.
    const record = await this.refresher.getFresh();
    if (this.disposed) throw new Error('AulaContext has been disposed');

    const sameTokens =
      this.client !== undefined &&
      this.cachedRecord !== undefined &&
      this.cachedRecord.tokens.access_token === record.tokens.access_token &&
      this.cachedRecord.tokens.refresh_token === record.tokens.refresh_token;
    if (sameTokens && this.client) {
      this.cachedRecord = record;
      return this.client;
    }

    if (this.client) {
      // Rotated (by us or out-of-band). Rebuilding rather than calling
      // setTokens() mirrors what the fs.watch invalidation always did in
      // production: the new client re-probes the API version and re-runs
      // the profile-context bootstrap against the new session, and the
      // widget manager — whose cached widget tokens were minted under the
      // old session — is dropped with it.
      this.logger.info('aula-context.tokens_rotated_rebuilding_client');
      this.widgetManager = undefined;
    }
    this.cachedRecord = record;
    this.client = new AulaClient({ tokens: record.tokens, http: this.http, logger: this.logger });
    return this.client;
  }
}

/**
 * Mirror the CLI's backend selection (apps/cli/src/store.ts) so the server
 * reads from the same place `aula login` writes to:
 *   1. AULA_MCP_NO_KEYCHAIN=1 → file backend regardless of platform.
 *   2. macOS + `security` available → KeychainTokenStore.
 *   3. Everything else → EncryptedFileTokenStore at AULA_MCP_DIR.
 */
function defaultStore(): TokenStore {
  if (KeychainTokenStore.isSupported() && process.env.AULA_MCP_NO_KEYCHAIN !== '1') {
    return new KeychainTokenStore();
  }
  const dir = process.env.AULA_MCP_DIR ?? join(homedir(), '.config', 'aula-mcp');
  return new EncryptedFileTokenStore({
    filePath: join(dir, 'tokens.json'),
    keyFilePath: join(dir, '.key'),
  });
}
