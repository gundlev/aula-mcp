/**
 * Setup / login UI.
 *
 * Standalone Hono app served on a second port (default 8099). Home Assistant
 * proxies it via Ingress, so the user opens "Aula" in HA's sidebar and gets
 * an interactive MitID login flow without ever leaving HA.
 *
 * Flow:
 *   1. GET  /            → HTML page. Shows token status + "Start login" button.
 *   2. POST /login/start → kicks off MitID APP-method login. Returns sessionId.
 *   3. GET  /login/events?sessionId=… → SSE stream:
 *        event: qr            data: { svg, refreshCount }
 *        event: otp           data: { code }
 *        event: verified      data: {}
 *        event: identity      data: { options: [{ index, name }] }
 *        event: success       data: { identityName?, expiresInSec }
 *        event: error         data: { message }
 *   4. POST /login/identity?sessionId=… { index } → resolves selectIdentity.
 *
 * The same `AulaLoginClient` the CLI uses runs here — no duplication of
 * MitID logic. We just translate its callbacks into SSE events.
 *
 * Access control (audit finding 5). The UI reads the household's login state
 * and can log the household out, so every route sits behind an administrator
 * check chosen with `AULA_MCP_SETUP_AUTH`:
 *   - `ingress`  — only requests arriving from Home Assistant's Ingress proxy
 *                  (`AULA_MCP_SETUP_TRUSTED_PROXIES`, default 172.30.32.2) are
 *                  served; HA has already authenticated the user.
 *   - `password` — HTTP Basic with `AULA_MCP_SETUP_PASSWORD` (any username).
 *   - `none`     — explicit opt-out, honoured only for a loopback bind.
 * There is no default: an unset mode is a configuration error, and the
 * standalone Coolify deployment never sets `AULA_MCP_INGRESS_PORT` at all.
 *
 * State-changing routes additionally require `X-Requested-With:
 * aula-mcp-setup` plus a JSON content type (a cross-origin page cannot add
 * either without a CORS preflight, which this app never grants) and, when
 * the browser sends it, a same-origin `Sec-Fetch-Site`.
 *
 * Login sessions are single-flight, rate-limited, time-boxed and removed on
 * a timer regardless of whether an event stream ever attached.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  AulaHttpClient,
  AulaLoginClient,
  EncryptedFileTokenStore,
  type IdentityOption,
  type Logger,
  type StoredTokenRecord,
  silentLogger,
  type TokenStore,
} from '@aula-mcp/aula-auth';
import { type Context, Hono, type Next } from 'hono';
import { type SSEStreamingApi, streamSSE } from 'hono/streaming';
import QRCode from 'qrcode';
import { isLoopbackHost } from './config.ts';

/** Max time we'll hold a login session waiting on the user to pick their
 *  MitID identity after the picker is shown. After this the login rejects
 *  with a timeout so the session entry gets cleaned up instead of leaking. */
const IDENTITY_PICK_TIMEOUT_MS = 5 * 60 * 1000;

export class SetupConfigError extends Error {
  override readonly name = 'SetupConfigError';
}

export type SetupAuthConfig =
  | { mode: 'ingress'; trustedProxies: string[] }
  | { mode: 'password'; passwordDigest: Buffer }
  | { mode: 'none' };

export const MIN_SETUP_PASSWORD_LENGTH = 16;
export const DEFAULT_HA_INGRESS_PROXY = '172.30.32.2';
export const CSRF_HEADER = 'x-requested-with';
export const CSRF_HEADER_VALUE = 'aula-mcp-setup';

export interface SetupLimits {
  /** Login sessions allowed to run at once. Default 1 (one household). */
  maxConcurrentLogins: number;
  /** `POST /login/start` calls accepted per window. Default 5. */
  loginStartsPerWindow: number;
  loginWindowMs: number;
  /** Hard cap on one login attempt, QR scanning included. Default 10 min. */
  loginTimeoutMs: number;
  /** How long a finished session stays addressable (so a late event stream
   *  can replay the terminal event) before it is dropped. Default 60 s. */
  sessionRetentionMs: number;
  /** Longest accepted MitID username. */
  maxUsernameLength: number;
}

export const DEFAULT_SETUP_LIMITS: SetupLimits = {
  maxConcurrentLogins: 1,
  loginStartsPerWindow: 5,
  loginWindowMs: 10 * 60 * 1000,
  loginTimeoutMs: 10 * 60 * 1000,
  sessionRetentionMs: 60 * 1000,
  maxUsernameLength: 64,
};

export interface SetupAppOptions {
  logger?: Logger;
  /** Override the token store (tests). Production uses the addon's
   *  EncryptedFileTokenStore under `AULA_MCP_DIR`. */
  store?: TokenStore;
  /** Administrator check. Loaded from the environment when omitted. */
  auth?: SetupAuthConfig;
  /** Interface the UI is bound to; decides whether `none` is acceptable. */
  bindHost?: string;
  limits?: Partial<SetupLimits>;
  /** Replace the MitID login runner (tests). */
  runLogin?: LoginRunner;
  now?: () => number;
}

/** What the HTTP layer knows about the peer. `remoteAddress` is the TCP
 *  peer as seen by Bun — never a forwarded header. */
export interface RequestInfo {
  remoteAddress?: string | null;
}

export interface SetupApp {
  fetch(request: Request, info?: RequestInfo): Response | Promise<Response>;
  /** Abort and drop every login session; stop timers. */
  close(): Promise<void>;
  stats(): { loginSessions: number; activeLogins: number };
}

export interface LoginSession {
  sessionId: string;
  username: string;
  startedAt: number;
  stream?: SSEStreamingApi;
  /** Resolver waiting on user identity choice; null when no pending pick. */
  pendingIdentity: ((index: number) => void) | null;
  /** Queue of events that arrived before the stream was attached. */
  bufferedEvents: Array<{ event: string; data: string }>;
  abort: AbortController;
  /** Set when the login resolves (success or error). */
  terminal?: { event: 'success' | 'error'; data: string };
  /** Resolves when the runner has finished (after the terminal event). */
  done: Promise<void>;
  signalDone: () => void;
}

export type LoginRunner = (session: LoginSession, store: TokenStore, logger: Logger) => Promise<void>;

const ICON_SVG = `<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 3 1 9l11 6 9-4.91V17h2V9z"/></svg>`;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * Resolve the administrator check from the environment. Throws
 * `SetupConfigError` unless one of the three modes is chosen explicitly and
 * fully configured; `none` additionally requires a loopback bind.
 */
export function loadSetupAuth(env: NodeJS.ProcessEnv, bindHost: string): SetupAuthConfig {
  const mode = env.AULA_MCP_SETUP_AUTH;
  switch (mode) {
    case 'ingress': {
      const proxies = (env.AULA_MCP_SETUP_TRUSTED_PROXIES ?? DEFAULT_HA_INGRESS_PROXY)
        .split(',')
        .map((s) => normaliseAddress(s.trim()))
        .filter(Boolean);
      if (proxies.length === 0) {
        throw new SetupConfigError('AULA_MCP_SETUP_TRUSTED_PROXIES must list at least one address.');
      }
      return { mode: 'ingress', trustedProxies: proxies };
    }
    case 'password': {
      let password = env.AULA_MCP_SETUP_PASSWORD ?? '';
      const file = env.AULA_MCP_SETUP_PASSWORD_FILE;
      if (!password && file) {
        try {
          password = readFileSync(file, 'utf8').trim();
        } catch (e) {
          throw new SetupConfigError(
            `AULA_MCP_SETUP_PASSWORD_FILE (${file}) could not be read: ${(e as Error).message}`,
          );
        }
      }
      if (password.length < MIN_SETUP_PASSWORD_LENGTH) {
        throw new SetupConfigError(
          `AULA_MCP_SETUP_AUTH=password needs AULA_MCP_SETUP_PASSWORD (or _FILE) of at least ` +
            `${MIN_SETUP_PASSWORD_LENGTH} characters.`,
        );
      }
      return { mode: 'password', passwordDigest: sha256(password) };
    }
    case 'none':
      if (!isLoopbackHost(bindHost)) {
        throw new SetupConfigError(
          `AULA_MCP_SETUP_AUTH=none is only allowed when the setup UI binds to loopback (it binds to ${bindHost}).`,
        );
      }
      return { mode: 'none' };
    case undefined:
    case '':
      throw new SetupConfigError(
        'The setup UI is enabled (AULA_MCP_INGRESS_PORT) but AULA_MCP_SETUP_AUTH is not set. Use ' +
          '"ingress" behind Home Assistant, "password" with AULA_MCP_SETUP_PASSWORD, or "none" for a ' +
          'loopback-only bind. Standalone deployments should leave AULA_MCP_INGRESS_PORT unset.',
      );
    default:
      throw new SetupConfigError(
        `AULA_MCP_SETUP_AUTH="${mode}" is not understood (use "ingress", "password" or "none").`,
      );
  }
}

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/** `::ffff:172.30.32.2` → `172.30.32.2`; lower-cases IPv6. */
export function normaliseAddress(address: string): string {
  const a = address.trim().toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  return mapped?.[1] ?? a;
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

export function createSetupApp(options: SetupAppOptions = {}): SetupApp {
  const logger = options.logger ?? silentLogger;
  const store = options.store ?? defaultAddonStore();
  const bindHost = options.bindHost ?? '127.0.0.1';
  const auth = options.auth ?? loadSetupAuth(process.env, bindHost);
  const limits: SetupLimits = { ...DEFAULT_SETUP_LIMITS, ...options.limits };
  const runner = options.runLogin ?? runLogin;
  const now = options.now ?? Date.now;

  const loginSessions = new Map<string, LoginSession>();
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const loginStarts: number[] = [];
  let closed = false;

  function schedule(fn: () => void, ms: number): void {
    const t = setTimeout(() => {
      timers.delete(t);
      fn();
    }, ms);
    t.unref?.();
    timers.add(t);
  }

  function activeLogins(): number {
    let n = 0;
    for (const s of loginSessions.values()) if (!s.terminal) n++;
    return n;
  }

  function dropSession(sessionId: string, reason: string): void {
    const s = loginSessions.get(sessionId);
    if (!s) return;
    loginSessions.delete(sessionId);
    if (!s.terminal) s.abort.abort();
    logger.info('setup.login.session_dropped', { reason });
  }

  /** Once a login has finished, keep it briefly for replay, then drop it. */
  function scheduleRetention(session: LoginSession): void {
    schedule(() => dropSession(session.sessionId, 'retention_elapsed'), limits.sessionRetentionMs);
  }

  const app = new Hono();

  // ---- administrator check (every route) ----------------------------------
  app.use('*', async (c, next) => {
    const info = (c.env as RequestInfo | undefined) ?? {};
    const verdict = authorise(auth, c.req.raw, info);
    if (verdict !== 'ok') {
      logger.warn('setup.access_denied', { reason: verdict, path: c.req.path });
      if (verdict === 'password_required') {
        c.header('www-authenticate', 'Basic realm="aula-mcp setup", charset="UTF-8"');
        return c.text('Authentication required', 401);
      }
      return c.text('Forbidden', 403);
    }
    await next();
    try {
      c.res.headers.set('cache-control', 'no-store');
      c.res.headers.set('x-content-type-options', 'nosniff');
      c.res.headers.set('referrer-policy', 'no-referrer');
      // HA embeds the page in its own frame under `ingress`; elsewhere
      // nobody legitimately frames it.
      c.res.headers.set(
        'content-security-policy',
        `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'` +
          (auth.mode === 'ingress' ? '' : "; frame-ancestors 'none'"),
      );
    } catch {
      // Immutable headers (streamed response) — fine.
    }
  });

  // ---- CSRF for anything that changes state --------------------------------
  const requireSameOriginJson = async (c: Context, next: Next) => {
    const fetchSite = c.req.header('sec-fetch-site');
    if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
      return c.json({ error: 'cross_site_request' }, 403);
    }
    if (c.req.header(CSRF_HEADER) !== CSRF_HEADER_VALUE) {
      return c.json({ error: `missing ${CSRF_HEADER}: ${CSRF_HEADER_VALUE} header` }, 403);
    }
    const type = c.req.header('content-type') ?? '';
    if (!/^application\/json\b/i.test(type)) {
      return c.json({ error: 'content-type must be application/json' }, 415);
    }
    await next();
  };
  app.use('/login/start', requireSameOriginJson);
  app.use('/login/identity', requireSameOriginJson);
  app.use('/logout', requireSameOriginJson);

  // ---- routes ----------------------------------------------------------------

  app.get('/', (c) => c.html(renderSetupPage()));

  app.get('/status', async (c) => {
    const record = await store.load();
    if (!record) return c.json({ logged_in: false });
    const nowSec = Math.floor(now() / 1000);
    return c.json({
      logged_in: true,
      username: record.username,
      identity_name: record.identityName ?? null,
      expires_at: record.tokens.expires_at,
      seconds_remaining: Math.max(0, record.tokens.expires_at - nowSec),
      saved_at: record.saved_at,
    });
  });

  app.post('/login/start', async (c) => {
    if (closed) return c.json({ error: 'shutting down' }, 503);
    let body: { username?: unknown };
    try {
      body = (await c.req.json()) as { username?: unknown };
    } catch {
      return c.json({ error: 'invalid JSON body' }, 400);
    }
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    if (!username) return c.json({ error: 'username is required' }, 400);
    if (username.length > limits.maxUsernameLength || /[\s\p{C}]/u.test(username)) {
      return c.json({ error: 'username must be a single word without control characters' }, 400);
    }

    // Rate limit: a MitID login is a human-paced action; a burst is abuse.
    const t = now();
    while (loginStarts.length > 0 && t - (loginStarts[0] as number) > limits.loginWindowMs) loginStarts.shift();
    if (loginStarts.length >= limits.loginStartsPerWindow) {
      c.header('retry-after', String(Math.ceil((limits.loginWindowMs - (t - (loginStarts[0] as number))) / 1000)));
      return c.json({ error: 'too many login attempts; try again later' }, 429);
    }
    if (activeLogins() >= limits.maxConcurrentLogins) {
      return c.json({ error: 'a login is already in progress' }, 409);
    }
    loginStarts.push(t);

    const sessionId = crypto.randomUUID();
    let signalDone!: () => void;
    const done = new Promise<void>((resolve) => {
      signalDone = resolve;
    });
    const session: LoginSession = {
      sessionId,
      username,
      startedAt: t,
      pendingIdentity: null,
      bufferedEvents: [],
      abort: new AbortController(),
      done,
      signalDone,
    };
    loginSessions.set(sessionId, session);

    // Time-box the whole attempt, then retain briefly for replay, then drop —
    // none of which depends on a browser ever attaching to /login/events.
    schedule(() => {
      if (!session.terminal) {
        logger.warn('setup.login.timed_out');
        session.abort.abort();
      }
    }, limits.loginTimeoutMs);
    void session.done.then(() => scheduleRetention(session));

    // Fire the login in the background; the route returns the sessionId
    // immediately so the browser can subscribe to /login/events.
    runner(session, store, logger).catch((err) => {
      logger.error('setup.login.unexpected_error', { error: (err as Error).message });
      if (!session.terminal) {
        session.terminal = { event: 'error', data: JSON.stringify({ message: 'login failed' }) };
      }
      session.signalDone();
    });

    return c.json({ sessionId });
  });

  app.get('/login/events', (c) => {
    const sessionId = c.req.query('sessionId');
    if (!sessionId) return c.json({ error: 'missing sessionId' }, 400);
    if (!UUID_RE.test(sessionId)) return c.json({ error: 'invalid sessionId' }, 400);
    const session = loginSessions.get(sessionId);
    if (!session) return c.json({ error: 'unknown sessionId' }, 404);

    return streamSSE(c, async (stream) => {
      session.stream = stream;

      // Drain any events buffered before the stream attached (including a
      // terminal event from a login that already finished).
      for (const ev of session.bufferedEvents) {
        await stream.writeSSE(ev);
      }
      session.bufferedEvents.length = 0;

      // Hold the stream open until either the user disconnects or the login
      // finishes. Cleanup is owned by the retention timer, not by this
      // handler, so a stream that never attaches changes nothing.
      const aborted = new Promise<'aborted'>((resolve) => {
        stream.onAbort(() => {
          session.abort.abort();
          resolve('aborted');
        });
      });
      const finished = session.done.then(() => 'finished' as const);
      await Promise.race([aborted, finished]);
      session.stream = undefined;
    });
  });

  app.post('/login/identity', async (c) => {
    const sessionId = c.req.query('sessionId');
    if (!sessionId) return c.json({ error: 'missing sessionId' }, 400);
    if (!UUID_RE.test(sessionId)) return c.json({ error: 'invalid sessionId' }, 400);
    const session = loginSessions.get(sessionId);
    if (!session) return c.json({ error: 'unknown sessionId' }, 404);
    if (!session.pendingIdentity) return c.json({ error: 'no pending identity choice' }, 409);
    let body: { index?: unknown };
    try {
      body = (await c.req.json()) as { index?: unknown };
    } catch {
      return c.json({ error: 'invalid JSON body' }, 400);
    }
    const index = typeof body.index === 'number' ? body.index : Number.NaN;
    // MitID identity indices are 1-based — `0` is treated as "no identity
    // selected" by the rest of the auth pipeline, so refuse it explicitly.
    if (!Number.isInteger(index) || index < 1 || index > 50) {
      return c.json({ error: 'index must be a positive integer' }, 400);
    }
    session.pendingIdentity(index);
    session.pendingIdentity = null;
    return c.body(null, 202);
  });

  app.post('/logout', async (c) => {
    await store.clear();
    logger.info('setup.logout');
    return c.json({ ok: true });
  });

  app.notFound((c) => c.text('Not Found', 404));
  app.onError((err, c) => {
    logger.error('setup.unhandled_error', { error: err.message, path: c.req.path });
    return c.json({ error: 'internal_error' }, 500);
  });

  return {
    fetch: (request, info = {}) => app.fetch(request, info),
    stats: () => ({ loginSessions: loginSessions.size, activeLogins: activeLogins() }),
    async close() {
      closed = true;
      for (const t of timers) clearTimeout(t);
      timers.clear();
      for (const id of Array.from(loginSessions.keys())) dropSession(id, 'shutdown');
    },
  };
}

// ---------------------------------------------------------------------------
// Authorisation
// ---------------------------------------------------------------------------

export type AuthVerdict = 'ok' | 'untrusted_peer' | 'password_required' | 'password_invalid';

export function authorise(auth: SetupAuthConfig, request: Request, info: RequestInfo): AuthVerdict {
  switch (auth.mode) {
    case 'none':
      return 'ok';
    case 'ingress': {
      // The TCP peer must be the Ingress proxy. Forwarded headers are not
      // consulted: anyone who can reach the port can forge those.
      const peer = info.remoteAddress ? normaliseAddress(info.remoteAddress) : '';
      return peer && auth.trustedProxies.includes(peer) ? 'ok' : 'untrusted_peer';
    }
    case 'password': {
      const header = request.headers.get('authorization') ?? '';
      const m = /^basic\s+([a-z0-9+/=_-]+)$/i.exec(header.trim());
      if (!m) return 'password_required';
      let decoded: string;
      try {
        decoded = Buffer.from(m[1] as string, 'base64').toString('utf8');
      } catch {
        return 'password_invalid';
      }
      const colon = decoded.indexOf(':');
      const password = colon === -1 ? '' : decoded.slice(colon + 1);
      if (!password) return 'password_required';
      return timingSafeEqual(sha256(password), auth.passwordDigest) ? 'ok' : 'password_invalid';
    }
  }
}

// ---------------------------------------------------------------------------
// Login runner
// ---------------------------------------------------------------------------

async function runLogin(session: LoginSession, store: TokenStore, logger: Logger): Promise<void> {
  const http = new AulaHttpClient({ logger });
  const client = new AulaLoginClient({ http, logger });
  let lastQrCount = -1;
  let identityName: string | undefined;
  let identityIndex: number | undefined;

  const emit = async (event: string, data: unknown): Promise<void> => {
    const payload = { event, data: JSON.stringify(data) };
    if (session.stream && !session.stream.aborted) {
      try {
        await session.stream.writeSSE(payload);
        return;
      } catch (err) {
        logger.error('setup.login.sse_write_error', { error: (err as Error).message });
      }
    }
    session.bufferedEvents.push(payload);
  };

  try {
    const tokens = await client.login({
      username: session.username,
      method: 'APP',
      signal: session.abort.signal,
      selectIdentity: async (options: IdentityOption[]) => {
        await emit('identity', {
          options: options.map((o) => ({ index: o.index, name: o.name })),
        });
        // Wait for the user to POST /login/identity, with two escape hatches:
        // (a) the session abort (browser closed the stream, or the overall
        //     login timeout fired) and
        // (b) a hard timeout so a user who walks away doesn't leak the
        //     session entry forever.
        const choice = await new Promise<number>((resolve, reject) => {
          let settled = false;
          const settle = (fn: () => void): void => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            session.abort.signal.removeEventListener('abort', onAbort);
            fn();
          };
          session.pendingIdentity = (idx) => settle(() => resolve(idx));
          const onAbort = (): void => settle(() => reject(new Error('aborted')));
          session.abort.signal.addEventListener('abort', onAbort, { once: true });
          const timer = setTimeout(
            () => settle(() => reject(new Error('identity selection timed out'))),
            IDENTITY_PICK_TIMEOUT_MS,
          );
        });
        session.pendingIdentity = null;
        identityIndex = choice;
        identityName = options.find((o) => o.index === choice)?.name;
        await emit('identity-selected', { index: choice, name: identityName ?? null });
        return choice;
      },
      appCallbacks: {
        onOtp: async (otp) => {
          await emit('otp', { code: otp });
        },
        onQr: async ({ qr1Json, qr2Json, updateCount }) => {
          if (updateCount === lastQrCount) return;
          lastQrCount = updateCount;
          const [svg1, svg2] = await Promise.all([
            QRCode.toString(qr1Json, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 }),
            QRCode.toString(qr2Json, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 }),
          ]);
          await emit('qr', { svg1, svg2, refreshCount: updateCount });
        },
        onVerified: async () => {
          await emit('verified', {});
        },
      },
    });

    const now = Math.floor(Date.now() / 1000);
    const record: StoredTokenRecord = {
      version: 1,
      username: session.username,
      tokens,
      saved_at: now,
      ...(identityIndex !== undefined ? { identityIndex } : {}),
      ...(identityName ? { identityName } : {}),
    };
    await store.save(record);

    const terminal = {
      event: 'success' as const,
      data: JSON.stringify({
        identityName: identityName ?? null,
        expiresInSec: Math.max(0, tokens.expires_at - now),
      }),
    };
    session.terminal = terminal;
    await emit('success', JSON.parse(terminal.data));
    logger.info('setup.login.success');
  } catch (err) {
    const error = err as Error;
    const terminal = {
      event: 'error' as const,
      data: JSON.stringify({ message: error.message, name: error.name ?? 'Error' }),
    };
    session.terminal = terminal;
    await emit('error', JSON.parse(terminal.data));
    // The username is the MitID login name — keep it out of the log line.
    logger.error('setup.login.failed', { name: error.name, message: error.message });
  } finally {
    // Always signal — the retention timer and any attached SSE stream wait
    // on this. Without it an unexpected throw could leak the entry.
    session.signalDone();
  }
}

function defaultAddonStore(): TokenStore {
  // Mirror AulaContext's default store path resolution: honour AULA_MCP_DIR
  // when set (the HA addon's run.sh exports it to /config/aula-mcp), and
  // otherwise fall back to ~/.config/aula-mcp so non-addon deployments (dev
  // boxes, VPS) don't try to write into a non-existent /config directory.
  const dir = process.env.AULA_MCP_DIR ?? join(homedir(), '.config', 'aula-mcp');
  return new EncryptedFileTokenStore({
    filePath: join(dir, 'tokens.json'),
    keyFilePath: join(dir, '.key'),
  });
}

function renderSetupPage(): string {
  // Inline single-page UI. Vanilla JS + EventSource so it works without a
  // build step inside the addon. Styling kept minimal to match HA's frame.
  return `<!doctype html>
<html lang="da">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>aula-mcp — login</title>
<style>
  :root { color-scheme: light dark; --fg: #1d1d1f; --muted: #6b7280; --bg: #ffffff; --card: #f7f7f8; --border: #e5e7eb; --accent: #03a9f4; --error: #b00020; --success: #117a3a; }
  @media (prefers-color-scheme: dark) { :root { --fg: #f5f5f7; --muted: #a1a1aa; --bg: #111114; --card: #1c1c1f; --border: #2a2a2e; } }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: var(--fg); background: var(--bg); margin: 0; padding: 2rem 1rem; }
  main { max-width: 640px; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin: 0 0 0.5rem; display: flex; align-items: center; gap: 0.5rem; }
  h1 svg { color: var(--accent); }
  p { color: var(--muted); margin: 0 0 1rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; margin: 1rem 0; }
  .qr-wrap { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin: 1rem 0; }
  .qr-wrap > div { background: #fff; border-radius: 8px; padding: 0.5rem; display: flex; align-items: center; justify-content: center; }
  .qr-wrap svg { width: 100%; height: auto; max-width: 240px; }
  label { display: block; font-weight: 500; margin-bottom: 0.25rem; }
  input[type=text] { width: 100%; padding: 0.6rem 0.75rem; font-size: 1rem; border: 1px solid var(--border); border-radius: 8px; background: var(--bg); color: var(--fg); }
  button { font: inherit; padding: 0.6rem 1.1rem; border-radius: 8px; border: 0; background: var(--accent); color: #fff; font-weight: 500; cursor: pointer; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  button.secondary { background: transparent; color: var(--fg); border: 1px solid var(--border); }
  .row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  .status-line { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; }
  .dot { width: 0.6rem; height: 0.6rem; border-radius: 50%; background: var(--muted); }
  .dot.ok { background: var(--success); }
  .dot.err { background: var(--error); }
  .stage { font-weight: 500; }
  .stage.error { color: var(--error); }
  .stage.success { color: var(--success); }
  .identity-options button { margin: 0.25rem 0.5rem 0.25rem 0; background: var(--card); color: var(--fg); border: 1px solid var(--border); }
  .muted { color: var(--muted); font-size: 0.85rem; }
  details { margin-top: 1rem; }
  summary { cursor: pointer; color: var(--muted); }
  code { background: var(--card); border: 1px solid var(--border); padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.9em; }
</style>
</head>
<body>
<main>
  <h1>${ICON_SVG} aula-mcp</h1>
  <p>Log ind med MitID, så HA's Assist + Voice kan tale med Aula.</p>

  <div class="card" id="status-card">
    <div class="status-line">
      <span class="dot" id="status-dot"></span>
      <span id="status-text">Indlæser status…</span>
    </div>
    <div id="status-detail" class="muted" style="margin-top: 0.5rem;"></div>
    <div class="row" id="status-actions" style="margin-top: 0.75rem;"></div>
  </div>

  <div class="card" id="login-card" hidden>
    <label for="username">MitID-brugernavn</label>
    <input type="text" id="username" placeholder="dit MitID-username" autocomplete="username" />
    <div class="row" style="margin-top: 0.75rem;">
      <button id="start-btn">Start login</button>
      <span class="muted">Du scanner QR-koden med MitID-appen.</span>
    </div>
  </div>

  <div class="card" id="progress-card" hidden>
    <div class="status-line">
      <span class="dot" id="progress-dot"></span>
      <span class="stage" id="stage">Starter…</span>
    </div>
    <div id="progress-detail" class="muted" style="margin-top: 0.5rem;"></div>
    <div class="qr-wrap" id="qr-wrap" hidden></div>
    <div id="identity-choice" hidden style="margin-top: 1rem;">
      <p style="margin: 0 0 0.5rem;">Du har flere identiteter — vælg den der hører til Aula:</p>
      <div class="identity-options" id="identity-options"></div>
    </div>
  </div>

  <details>
    <summary>Hvad sker der her?</summary>
    <p class="muted">Login-flow'et kører lokalt i din HA-installation. MitID-godkendelsen sker mellem MitID-appen og <code>nemlog-in.mitid.dk</code> — denne side ser kun de OAuth-tokens du får tilbage, og gemmer dem krypteret i <code>/config/aula-mcp/</code>. Tokens forlader ikke din HA.</p>
  </details>
</main>

<script>
const $ = (id) => document.getElementById(id);
// State-changing calls carry a custom header + JSON type: a cross-origin page
// cannot send either without a CORS preflight, which the server never grants.
const POST_HEADERS = { 'content-type': 'application/json', 'x-requested-with': 'aula-mcp-setup' };
const statusDot = $('status-dot');
const statusText = $('status-text');
const statusDetail = $('status-detail');
const statusActions = $('status-actions');
const loginCard = $('login-card');
const progressCard = $('progress-card');
const progressDot = $('progress-dot');
const stage = $('stage');
const progressDetail = $('progress-detail');
const qrWrap = $('qr-wrap');
const identityChoice = $('identity-choice');
const identityOptions = $('identity-options');
const startBtn = $('start-btn');
const usernameInput = $('username');

let currentSessionId = null;
let currentSource = null;

async function refreshStatus() {
  const res = await fetch('status');
  const data = await res.json();
  if (data.logged_in) {
    statusDot.classList.add('ok');
    statusDot.classList.remove('err');
    statusText.textContent = 'Logget ind';
    const expiresMin = Math.round(data.seconds_remaining / 60);
    statusDetail.textContent = (data.identity_name ? data.identity_name + ' — ' : '') +
      (data.username) + '. Access token udløber om ' + expiresMin + ' min.';
    statusActions.innerHTML = '';
    const logoutBtn = document.createElement('button');
    logoutBtn.textContent = 'Log ud';
    logoutBtn.className = 'secondary';
    logoutBtn.onclick = async () => {
      await fetch('logout', { method: 'POST', headers: POST_HEADERS, body: '{}' });
      await refreshStatus();
    };
    statusActions.appendChild(logoutBtn);
    loginCard.hidden = true;
  } else {
    statusDot.classList.remove('ok', 'err');
    statusText.textContent = 'Ikke logget ind';
    statusDetail.textContent = 'Klik nedenfor for at starte MitID-login.';
    statusActions.innerHTML = '';
    loginCard.hidden = false;
  }
}

function setStage(text, kind = '') {
  stage.textContent = text;
  stage.classList.remove('error', 'success');
  if (kind) stage.classList.add(kind);
  progressDot.classList.remove('ok', 'err');
  if (kind === 'success') progressDot.classList.add('ok');
  if (kind === 'error') progressDot.classList.add('err');
}

function showQR(svg1, svg2, refresh) {
  qrWrap.hidden = false;
  qrWrap.innerHTML = '<div>' + svg1 + '</div><div>' + svg2 + '</div>';
  progressDetail.textContent = 'Scan en af QR-koderne med MitID-appen (skifter automatisk).';
}

function showIdentityChoice(options) {
  identityChoice.hidden = false;
  identityOptions.innerHTML = '';
  for (const opt of options) {
    const btn = document.createElement('button');
    btn.textContent = opt.name;
    btn.onclick = async () => {
      identityOptions.innerHTML = '<span class="muted">Vælger ' + opt.name + '…</span>';
      await fetch('login/identity?sessionId=' + encodeURIComponent(currentSessionId), {
        method: 'POST',
        headers: POST_HEADERS,
        body: JSON.stringify({ index: opt.index }),
      });
    };
    identityOptions.appendChild(btn);
  }
}

startBtn.onclick = async () => {
  const username = usernameInput.value.trim();
  if (!username) {
    usernameInput.focus();
    return;
  }
  startBtn.disabled = true;
  loginCard.hidden = true;
  progressCard.hidden = false;
  qrWrap.hidden = true;
  identityChoice.hidden = true;
  setStage('Starter login…');
  progressDetail.textContent = '';

  const res = await fetch('login/start', {
    method: 'POST',
    headers: POST_HEADERS,
    body: JSON.stringify({ username }),
  });
  if (!res.ok) {
    setStage('Kunne ikke starte login', 'error');
    progressDetail.textContent = 'HTTP ' + res.status + ' — tjek log.';
    startBtn.disabled = false;
    return;
  }
  const { sessionId } = await res.json();
  currentSessionId = sessionId;

  currentSource = new EventSource('login/events?sessionId=' + encodeURIComponent(sessionId));

  currentSource.addEventListener('qr', (ev) => {
    setStage('Venter på MitID');
    const data = JSON.parse(ev.data);
    showQR(data.svg1, data.svg2, data.refreshCount);
  });
  currentSource.addEventListener('otp', (ev) => {
    const data = JSON.parse(ev.data);
    setStage('Indtast OTP i MitID-appen');
    progressDetail.textContent = 'Kode: ' + data.code;
  });
  currentSource.addEventListener('verified', () => {
    setStage('Bekræft i MitID-appen');
    progressDetail.textContent = 'Godkend login i MitID-appen.';
  });
  currentSource.addEventListener('identity', (ev) => {
    setStage('Vælg identitet');
    const data = JSON.parse(ev.data);
    showIdentityChoice(data.options);
  });
  currentSource.addEventListener('identity-selected', () => {
    identityChoice.hidden = true;
    setStage('Fortsætter…');
  });
  currentSource.addEventListener('success', async (ev) => {
    setStage('Logget ind 🎉', 'success');
    const data = JSON.parse(ev.data);
    progressDetail.textContent = 'Tokens gemt. ' +
      (data.identityName ? 'Identitet: ' + data.identityName + '. ' : '') +
      'Access udløber om ' + Math.round((data.expiresInSec || 0) / 60) + ' min.';
    currentSource.close();
    startBtn.disabled = false;
    await refreshStatus();
  });
  currentSource.addEventListener('error', (ev) => {
    if (!ev.data) return;
    setStage('Login fejlede', 'error');
    try {
      const data = JSON.parse(ev.data);
      progressDetail.textContent = data.message || 'Ukendt fejl.';
    } catch {
      progressDetail.textContent = 'Forbindelsen blev afbrudt.';
    }
    currentSource.close();
    startBtn.disabled = false;
  });
};

refreshStatus();
</script>
</body>
</html>`;
}
