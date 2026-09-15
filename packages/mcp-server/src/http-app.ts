/**
 * The Hono application behind the HTTP MCP server, built from a
 * `ServerConfig` so it can be exercised in-process by tests and served by
 * `server.ts` in production.
 *
 * Request pipeline (audit finding 1):
 *   1. Host header must be loopback or on `allowedHosts` — otherwise 421.
 *      Browsers hitting a rebound DNS name send the attacker's Host; MCP
 *      clients send the name they were configured with.
 *   2. Origin, when present, must be on `allowedOrigins` (or name an allowed
 *      host) — otherwise 403. Non-browser clients omit Origin and are fine.
 *   3. A process-wide request budget (requests/minute) — otherwise 429.
 *   4. Every MCP route (`/mcp`, `/sse`, `/messages`) requires
 *      `Authorization: Bearer <token>` unless auth mode is `none`. Failures
 *      are counted; past the budget the routes answer 429 without checking.
 *      The credential never reaches a log line.
 *   5. POST bodies are read up to `maxBodyBytes` — otherwise 413 — and
 *      in-flight POSTs are capped — otherwise 503.
 *
 * `/healthz` (liveness) and `/readyz` (usable Aula credentials) skip step 4
 * so a container health check needs no secret; they carry no account data.
 *
 * Sessions: one McpApp + transport per Streamable HTTP session (and per
 * legacy SSE connection when enabled), capped and idle-evicted. Closing a
 * session disposes its AulaContext so file watchers do not accumulate
 * (audit finding 7).
 */

import { timingSafeEqual } from 'node:crypto';
import type { Logger } from '@aula-mcp/aula-auth';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { type Context, Hono, type Next } from 'hono';
import { streamSSE } from 'hono/streaming';
import { digest, isLoopbackHost, type ServerConfig } from './config.ts';
import { createMcpApp, type McpApp } from './setup.ts';
import { HonoSseTransport } from './sse-transport.ts';

export interface Readiness {
  ready: boolean;
  /** Coarse, non-identifying: `no_tokens`, `refresh_failing`, `store_error`. */
  reason?: string;
}

export interface HttpAppDeps {
  config: ServerConfig;
  logger: Logger;
  /** Builds the per-session MCP server + context. Tests inject a fake. */
  createApp?: (opts: { logger: Logger }) => McpApp;
  /** Answers `/readyz`. Defaults to "always ready" when not supplied. */
  readiness?: () => Promise<Readiness>;
  /** Clock, for tests. */
  now?: () => number;
}

export interface HttpApp {
  app: Hono;
  fetch: (request: Request) => Response | Promise<Response>;
  /** Close every session and stop the sweepers. */
  shutdown(): Promise<void>;
  /** Evict sessions idle for longer than the configured limit. */
  sweep(now?: number): void;
  stats(): { httpSessions: number; sseSessions: number; inFlight: number };
}

interface HttpSession {
  transport: WebStandardStreamableHTTPServerTransport;
  app: McpApp;
  lastActivityAt: number;
}

interface SseSession {
  transport: HonoSseTransport;
  app: McpApp;
  lastActivityAt: number;
  /** Lets the streaming route handler return once the server closes the session. */
  settle: () => void;
}

const BEARER_PREFIX = /^bearer\s+/i;

export function createHttpApp(deps: HttpAppDeps): HttpApp {
  const { config, logger } = deps;
  const createApp = deps.createApp ?? createMcpApp;
  const now = deps.now ?? Date.now;
  const readiness = deps.readiness ?? (async () => ({ ready: true }));

  const httpSessions = new Map<string, HttpSession>();
  const sseSessions = new Map<string, SseSession>();
  let inFlight = 0;

  // ---- budgets ------------------------------------------------------------

  const requestWindow = new FixedWindow(config.requestsPerMinute, 60_000, now);
  const authFailureWindow = new FixedWindow(config.authFailuresPerMinute, 60_000, now);

  // ---- session lifecycle --------------------------------------------------

  async function disposeApp(app: McpApp, kind: string, sessionId: string, reason: string) {
    try {
      await app.mcp.close();
    } catch (err) {
      logger.error(`aula-mcp.${kind}.mcp_close_error`, {
        sessionId,
        reason,
        error: (err as Error).message,
      });
    }
    try {
      app.context.dispose();
    } catch (err) {
      logger.error(`aula-mcp.${kind}.context_dispose_error`, {
        sessionId,
        reason,
        error: (err as Error).message,
      });
    }
  }

  async function closeHttpSession(sessionId: string, reason: string): Promise<void> {
    const session = httpSessions.get(sessionId);
    if (!session) return;
    httpSessions.delete(sessionId);
    try {
      await session.transport.close();
    } catch (err) {
      logger.error('aula-mcp.http.transport_close_error', {
        sessionId,
        reason,
        error: (err as Error).message,
      });
    }
    await disposeApp(session.app, 'http', sessionId, reason);
    logger.info('aula-mcp.http.session_closed', { sessionId, reason });
  }

  async function closeSseSession(sessionId: string, reason: string): Promise<void> {
    const session = sseSessions.get(sessionId);
    if (!session) return;
    sseSessions.delete(sessionId);
    try {
      await session.transport.close();
    } catch (err) {
      logger.error('aula-mcp.sse.transport_close_error', {
        sessionId,
        reason,
        error: (err as Error).message,
      });
    }
    await disposeApp(session.app, 'sse', sessionId, reason);
    session.settle();
    logger.info('aula-mcp.sse.session_closed', { sessionId, reason });
  }

  function sweep(at: number = now()): void {
    for (const [sessionId, session] of httpSessions) {
      if (at - session.lastActivityAt > config.httpIdleMs) {
        logger.info('aula-mcp.http.session_evicted_idle', { sessionId });
        void closeHttpSession(sessionId, 'idle');
      }
    }
    for (const [sessionId, session] of sseSessions) {
      if (at - session.lastActivityAt > config.sseIdleMs) {
        logger.info('aula-mcp.sse.session_evicted_idle', { sessionId });
        void closeSseSession(sessionId, 'idle');
      }
    }
  }

  const sweepInterval = Math.max(
    1_000,
    Math.floor(Math.min(config.httpIdleMs, config.sseIdleMs) / 4),
  );
  const sweeper = setInterval(() => sweep(), sweepInterval);
  sweeper.unref?.();

  // ---- middleware ---------------------------------------------------------

  const app = new Hono();

  // 1 + 2: Host and Origin.
  app.use('*', async (c, next) => {
    const host = c.req.header('host');
    if (!host) return c.text('Host header required', 400);
    if (!hostHeaderAllowed(host, config)) {
      logger.warn('aula-mcp.http.host_rejected', { host: host.slice(0, 100) });
      return c.text('Misdirected Request', 421);
    }
    const origin = c.req.header('origin');
    if (origin !== undefined && !originAllowed(origin, config)) {
      logger.warn('aula-mcp.http.origin_rejected', { origin: origin.slice(0, 100) });
      return c.text('Origin not allowed', 403);
    }
    await next();
    // Nothing here is cacheable, and nothing should be sniffed. Set after the
    // handler ran so the headers also land on raw Responses returned by the
    // MCP transport.
    try {
      c.res.headers.set('cache-control', 'no-store');
      c.res.headers.set('x-content-type-options', 'nosniff');
    } catch {
      // Immutable response headers — nothing sensitive to add anyway.
    }
  });

  // 3: global request budget.
  app.use('*', async (c, next) => {
    if (!requestWindow.take()) {
      c.header('retry-after', String(Math.ceil(requestWindow.msUntilReset() / 1000)));
      return c.json({ error: 'rate_limited' }, 429);
    }
    await next();
  });

  // 4: client authentication for every MCP route. The credential is checked
  // first so a flood of bad guesses can never lock out the real client; the
  // failure budget only changes what the *failing* requests get back.
  const requireAuth = async (c: Context, next: Next) => {
    if (config.auth.mode === 'none') return next();
    const header = c.req.header('authorization');
    const verdict = checkBearer(header, config.auth.tokenDigest);
    if (verdict === 'ok') return next();
    if (!authFailureWindow.take()) {
      c.header('retry-after', String(Math.ceil(authFailureWindow.msUntilReset() / 1000)));
      return c.json({ error: 'too_many_failed_authentications' }, 429);
    }
    // `verdict` is a category, never the presented value.
    logger.warn('aula-mcp.http.auth_failed', { reason: verdict, path: c.req.path });
    c.header('www-authenticate', 'Bearer realm="aula-mcp"');
    return c.json({ error: 'unauthorized' }, 401);
  };
  app.use('/mcp', requireAuth);
  app.use('/mcp/*', requireAuth);
  app.use('/sse', requireAuth);
  app.use('/sse/*', requireAuth);
  app.use('/messages', requireAuth);
  app.use('/messages/*', requireAuth);

  // ---- health -------------------------------------------------------------

  app.get('/healthz', (c) => c.json({ ok: true, name: 'aula-mcp' }));

  app.get('/readyz', async (c) => {
    let state: Readiness;
    try {
      state = await readiness();
    } catch (err) {
      logger.error('aula-mcp.readyz_error', { error: (err as Error).message });
      state = { ready: false, reason: 'store_error' };
    }
    return c.json(state, state.ready ? 200 : 503);
  });

  // ---- Streamable HTTP ----------------------------------------------------

  async function handleMcp(request: Request): Promise<Response> {
    const sessionId = request.headers.get('mcp-session-id');

    if (sessionId) {
      const session = httpSessions.get(sessionId);
      if (!session) return jsonRpcError(-32001, 'Session not found', 404);
      session.lastActivityAt = now();
      return session.transport.handleRequest(request);
    }

    // No session id: only an initialize request may create one. The
    // transport itself validates that the body is one.
    if (httpSessions.size >= config.httpMaxSessions) {
      logger.warn('aula-mcp.http.session_rejected_cap', {
        active: httpSessions.size,
        cap: config.httpMaxSessions,
      });
      return jsonRpcError(
        -32000,
        `Too many active MCP sessions (cap ${config.httpMaxSessions}). Retry shortly.`,
        503,
      );
    }

    let createdSessionId: string | undefined;
    const sessionApp = createApp({ logger });
    const transport = new WebStandardStreamableHTTPServerTransport({
      enableJsonResponse: true,
      sessionIdGenerator: () => crypto.randomUUID(),
      onsessioninitialized: (newSessionId) => {
        createdSessionId = newSessionId;
        httpSessions.set(newSessionId, {
          transport,
          app: sessionApp,
          lastActivityAt: now(),
        });
        logger.info('aula-mcp.http.session_initialized', { sessionId: newSessionId });
      },
      onsessionclosed: (closedSessionId) => {
        // Orderly DELETE /mcp. The transport is already closing itself;
        // release the McpServer and the context's file watcher.
        const session = httpSessions.get(closedSessionId);
        httpSessions.delete(closedSessionId);
        if (session) void disposeApp(session.app, 'http', closedSessionId, 'client_delete');
        logger.info('aula-mcp.http.session_closed', {
          sessionId: closedSessionId,
          reason: 'client_delete',
        });
      },
    });

    await sessionApp.mcp.connect(transport);
    try {
      const response = await transport.handleRequest(request);
      if (!createdSessionId) {
        // Initialization failed: nothing references this pair.
        await transport.close().catch(() => {});
        await disposeApp(sessionApp, 'http', 'uninitialized', 'init_failed');
      }
      return response;
    } catch (err) {
      if (!createdSessionId) {
        await transport.close().catch(() => {});
        await disposeApp(sessionApp, 'http', 'uninitialized', 'init_threw');
      }
      throw err;
    }
  }

  // 5: body + concurrency limits apply to the POST channels.
  async function boundedPost(
    c: Context,
    handler: (request: Request) => Promise<Response>,
  ): Promise<Response> {
    if (inFlight >= config.maxConcurrentRequests) {
      c.header('retry-after', '1');
      return c.json({ error: 'too_many_concurrent_requests' }, 503);
    }
    inFlight++;
    try {
      const bounded = await readBoundedRequest(c.req.raw, config.maxBodyBytes);
      if (!bounded)
        return c.json({ error: 'payload_too_large', maxBytes: config.maxBodyBytes }, 413);
      return await handler(bounded);
    } finally {
      inFlight--;
    }
  }

  app.post('/mcp', (c) => boundedPost(c, handleMcp));
  app.get('/mcp', (c) => handleMcp(c.req.raw));
  app.delete('/mcp', (c) => handleMcp(c.req.raw));

  // ---- Legacy SSE (opt-in) ------------------------------------------------

  if (config.legacySse) {
    app.get('/sse', (c) => {
      if (sseSessions.size >= config.sseMaxSessions) {
        logger.warn('aula-mcp.sse.session_rejected_cap', {
          active: sseSessions.size,
          cap: config.sseMaxSessions,
        });
        return c.json({ error: 'sse session cap reached' }, 503);
      }
      return streamSSE(c, async (stream) => {
        const sessionId = crypto.randomUUID();
        const sseTransport = new HonoSseTransport({
          sessionId,
          messageEndpoint: '/messages',
          stream,
          onActivity: () => {
            const s = sseSessions.get(sessionId);
            if (s) s.lastActivityAt = now();
          },
        });
        const sessionApp = createApp({ logger });
        let settle: () => void = () => {};
        const closed = new Promise<void>((resolve) => {
          settle = resolve;
        });
        sseSessions.set(sessionId, {
          transport: sseTransport,
          app: sessionApp,
          lastActivityAt: now(),
          settle,
        });
        stream.onAbort(() => {
          void closeSseSession(sessionId, 'abort');
        });
        try {
          await sessionApp.mcp.connect(sseTransport);
          logger.info('aula-mcp.sse.session_opened', { sessionId });
        } catch (err) {
          logger.error('aula-mcp.sse.connect_failed', {
            sessionId,
            error: (err as Error).message,
          });
          await closeSseSession(sessionId, 'connect_failed');
          return;
        }
        await closed;
      });
    });

    app.post('/messages', (c) =>
      boundedPost(c, async (request) => {
        const sessionId = new URL(request.url).searchParams.get('sessionId');
        if (!sessionId)
          return Response.json({ error: 'missing sessionId query parameter' }, { status: 400 });
        const session = sseSessions.get(sessionId);
        if (!session) return Response.json({ error: 'unknown sessionId' }, { status: 404 });
        let body: unknown;
        try {
          body = await request.json();
        } catch {
          return Response.json({ error: 'invalid JSON body' }, { status: 400 });
        }
        session.lastActivityAt = now();
        session.transport.receive(body);
        return new Response(null, { status: 202 });
      }),
    );
  }

  // Anything else — including /sse and /messages when the legacy transport
  // is off — is a plain 404 with no hint about what exists.
  app.notFound((c) => c.text('Not Found', 404));
  app.onError((err, c) => {
    logger.error('aula-mcp.http.unhandled_error', { error: err.message, path: c.req.path });
    return c.json({ error: 'internal_error' }, 500);
  });

  return {
    app,
    fetch: (request) => app.fetch(request),
    sweep,
    stats: () => ({ httpSessions: httpSessions.size, sseSessions: sseSessions.size, inFlight }),
    async shutdown() {
      clearInterval(sweeper);
      await Promise.all([
        ...Array.from(sseSessions.keys()).map((sid) => closeSseSession(sid, 'shutdown')),
        ...Array.from(httpSessions.keys()).map((sid) => closeHttpSession(sid, 'shutdown')),
      ]);
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonRpcError(code: number, message: string, status: number): Response {
  return Response.json({ jsonrpc: '2.0', error: { code, message }, id: null }, { status });
}

/**
 * Split `host[:port]` (with IPv6 brackets) into lower-cased parts.
 * Returns null for values that cannot be a Host header.
 */
export function splitHostHeader(value: string): { host: string; port: string | null } | null {
  const v = value.trim().toLowerCase();
  if (!v || /[\s/\\?#@]/.test(v)) return null;
  const m = /^(\[[0-9a-f:.]+\]|[^:]+)(?::(\d{1,5}))?$/.exec(v);
  if (!m) return null;
  const host = (m[1] as string).replace(/\.$/, '');
  return { host, port: m[2] ?? null };
}

/** Loopback is always accepted; otherwise the header must match an entry. */
export function hostHeaderAllowed(
  value: string,
  config: Pick<ServerConfig, 'allowedHosts'>,
): boolean {
  const parsed = splitHostHeader(value);
  if (!parsed) return false;
  if (isLoopbackHost(parsed.host)) return true;
  for (const entry of config.allowedHosts) {
    const e = splitHostHeader(entry);
    if (!e) continue;
    if (e.host !== parsed.host) continue;
    if (e.port === null || e.port === parsed.port) return true;
  }
  return false;
}

/**
 * An Origin is accepted when it is listed explicitly, or when it names an
 * allowed host (a same-origin page served from the public hostname).
 * `null`, unparsable and loopback origins are refused: this server serves
 * no pages of its own, so a page on `http://localhost:<port>` is just
 * another origin and must be allow-listed like any other.
 */
export function originAllowed(
  value: string,
  config: Pick<ServerConfig, 'allowedHosts' | 'allowedOrigins'>,
): boolean {
  const v = value.trim().toLowerCase();
  if (!v || v === 'null') return false;
  let url: URL;
  try {
    url = new URL(v);
  } catch {
    return false;
  }
  if (url.origin === 'null') return false;
  if (config.allowedOrigins.includes(url.origin)) return true;
  const parsed = splitHostHeader(url.host);
  if (!parsed) return false;
  for (const entry of config.allowedHosts) {
    const e = splitHostHeader(entry);
    if (!e || e.host !== parsed.host) continue;
    if (e.port === null || e.port === parsed.port) return true;
  }
  return false;
}

/** Constant-time bearer check against the configured token's digest. */
export function checkBearer(
  header: string | undefined,
  expectedDigest: Buffer,
): 'ok' | 'missing' | 'malformed' | 'invalid' {
  if (!header) return 'missing';
  if (!BEARER_PREFIX.test(header)) return 'malformed';
  const presented = header.replace(BEARER_PREFIX, '').trim();
  if (!presented || /\s/.test(presented)) return 'malformed';
  return timingSafeEqual(digest(presented), expectedDigest) ? 'ok' : 'invalid';
}

/**
 * Read up to `max` bytes of the request body and return an equivalent
 * Request carrying the buffered body, or null when the body is larger.
 * Guards both a declared Content-Length and a chunked body that lies.
 */
export async function readBoundedRequest(request: Request, max: number): Promise<Request | null> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > max) return null;
  if (!request.body) return request;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const body = Buffer.concat(chunks);
  const headers = new Headers(request.headers);
  headers.set('content-length', String(body.length));
  return new Request(request.url, { method: request.method, headers, body });
}

/** Fixed-window counter: `limit` events per `windowMs`. */
class FixedWindow {
  private count = 0;
  private windowStart: number;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly now: () => number,
  ) {
    this.windowStart = now();
  }

  private roll(): void {
    const t = this.now();
    if (t - this.windowStart >= this.windowMs) {
      this.windowStart = t;
      this.count = 0;
    }
  }

  /** Consume one unit; false when the window is exhausted. */
  take(): boolean {
    this.roll();
    if (this.count >= this.limit) return false;
    this.count++;
    return true;
  }

  msUntilReset(): number {
    return Math.max(0, this.windowStart + this.windowMs - this.now());
  }
}
