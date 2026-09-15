/**
 * Transport-level security tests for the HTTP MCP server (audit finding 1,
 * plus the session-disposal half of finding 7).
 *
 * The audit initialised the real server without any credential and listed
 * its tools. Every route is exercised here through `createHttpApp` with a
 * synthetic bearer token, a fake per-session McpApp (so `dispose()` calls
 * can be counted) and a controllable clock for the rate/idle windows.
 */

import { afterEach, describe, expect, test } from 'bun:test';
import type { Logger } from '@aula-mcp/aula-auth';
import { silentLogger } from '@aula-mcp/aula-auth';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AulaContext } from './aula-context.ts';
import { digest, loadServerConfig, type ServerConfig } from './config.ts';
import {
  checkBearer,
  createHttpApp,
  type HttpApp,
  hostHeaderAllowed,
  originAllowed,
  readBoundedRequest,
  splitHostHeader,
} from './http-app.ts';
import type { McpApp } from './setup.ts';

const TOKEN = 'synthetic-client-token-0123456789abcdef0123456789abcdef';
const PUBLIC_HOST = 'aula-mcp.example.com';

function config(env: Record<string, string> = {}): ServerConfig {
  return loadServerConfig({
    AULA_MCP_HOST: '0.0.0.0',
    AULA_MCP_ALLOW_REMOTE: '1',
    AULA_MCP_AUTH_TOKEN: TOKEN,
    AULA_MCP_ALLOWED_HOSTS: PUBLIC_HOST,
    ...env,
  });
}

/** Per-session fake: a real McpServer with two tools and a countable context. */
interface Fixture {
  disposed: string[];
  created: number;
  /** Resolve to let every in-flight `block` tool call finish. */
  release: () => void;
  createApp: (opts: { logger: Logger }) => McpApp;
}

function fixture(): Fixture {
  const disposed: string[] = [];
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const fx: Fixture = {
    disposed,
    created: 0,
    release: () => release(),
    createApp: () => {
      fx.created++;
      const mcp = new McpServer(
        { name: 'fake', version: '0.0.0' },
        { capabilities: { tools: {} } },
      );
      mcp.registerTool('ping', { description: 'ping' }, async () => ({
        content: [{ type: 'text', text: 'pong' }],
      }));
      mcp.registerTool('block', { description: 'waits for the test' }, async () => {
        await gate;
        return { content: [{ type: 'text', text: 'released' }] };
      });
      const id = `ctx-${fx.created}`;
      const context = { dispose: () => disposed.push(id) } as unknown as AulaContext;
      return { mcp, context };
    },
  };
  return fx;
}

interface ClientOptions {
  auth?: string | null;
  host?: string;
  origin?: string;
  sessionId?: string;
}

const INITIALIZE = {
  jsonrpc: '2.0',
  id: 0,
  method: 'initialize',
  params: {
    protocolVersion: '2025-03-26',
    capabilities: {},
    clientInfo: { name: 'test-client', version: '0.0.0' },
  },
};

function headers(opts: ClientOptions): Record<string, string> {
  const h: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    host: opts.host ?? PUBLIC_HOST,
  };
  if (opts.auth !== null) h.authorization = opts.auth ?? `Bearer ${TOKEN}`;
  if (opts.origin) h.origin = opts.origin;
  if (opts.sessionId) h['mcp-session-id'] = opts.sessionId;
  return h;
}

function post(
  app: HttpApp,
  path: string,
  body: unknown,
  opts: ClientOptions = {},
): Promise<Response> {
  return Promise.resolve(
    app.fetch(
      new Request(`https://${opts.host ?? PUBLIC_HOST}${path}`, {
        method: 'POST',
        headers: headers(opts),
        body: typeof body === 'string' ? body : JSON.stringify(body),
      }),
    ),
  );
}

function request(
  app: HttpApp,
  method: string,
  path: string,
  opts: ClientOptions = {},
): Promise<Response> {
  return Promise.resolve(
    app.fetch(
      new Request(`https://${opts.host ?? PUBLIC_HOST}${path}`, { method, headers: headers(opts) }),
    ),
  );
}

/** Full handshake; returns the session id the server allocated. */
async function initialize(app: HttpApp, opts: ClientOptions = {}): Promise<string> {
  const res = await post(app, '/mcp', INITIALIZE, opts);
  expect(res.status).toBe(200);
  const sessionId = res.headers.get('mcp-session-id');
  if (!sessionId) throw new Error('no session id');
  const ack = await post(
    app,
    '/mcp',
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { ...opts, sessionId },
  );
  expect(ack.status).toBe(202);
  return sessionId;
}

async function rpcResult(
  res: Response,
): Promise<{ result?: unknown; error?: { code: number; message: string } }> {
  const text = await res.text();
  if (res.headers.get('content-type')?.includes('text/event-stream')) {
    const line = text.split('\n').find((l) => l.startsWith('data:'));
    return JSON.parse((line ?? '').slice(5)) as never;
  }
  return JSON.parse(text) as never;
}

async function listTools(
  app: HttpApp,
  sessionId: string,
  opts: ClientOptions = {},
): Promise<string[]> {
  const res = await post(
    app,
    '/mcp',
    { jsonrpc: '2.0', id: 1, method: 'tools/list' },
    { ...opts, sessionId },
  );
  expect(res.status).toBe(200);
  const body = (await rpcResult(res)) as { result: { tools: Array<{ name: string }> } };
  return body.result.tools.map((t) => t.name);
}

const apps: HttpApp[] = [];
let clock = 1_000_000;
function build(
  cfg: ServerConfig,
  fx: Fixture,
  readiness?: () => Promise<{ ready: boolean; reason?: string }>,
) {
  const app = createHttpApp({
    config: cfg,
    logger: silentLogger,
    createApp: fx.createApp,
    now: () => clock,
    ...(readiness ? { readiness } : {}),
  });
  apps.push(app);
  return app;
}

afterEach(async () => {
  for (const app of apps.splice(0)) await app.shutdown();
});

// ---------------------------------------------------------------------------

describe('HTTP MCP server: client authentication', () => {
  test('initialize without Authorization is refused with 401 and no tool list', async () => {
    const fx = fixture();
    const app = build(config(), fx);
    const res = await post(app, '/mcp', INITIALIZE, { auth: null });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('Bearer');
    expect(res.headers.get('mcp-session-id')).toBeNull();
    expect(await res.json()).toEqual({ error: 'unauthorized' });
    // No per-session server was even constructed for the anonymous caller.
    expect(fx.created).toBe(0);
    expect(app.stats().httpSessions).toBe(0);
  });

  test('a wrong token, a non-bearer scheme and a case-variant token are all 401', async () => {
    const app = build(config(), fixture());
    for (const auth of [
      'Bearer definitely-not-the-token-000000000000000000000000000',
      `Basic ${Buffer.from(`user:${TOKEN}`).toString('base64')}`,
      `Bearer ${TOKEN.toUpperCase()}`,
      `Bearer ${TOKEN} extra`,
      'Bearer',
    ]) {
      const res = await post(app, '/mcp', INITIALIZE, { auth });
      expect(res.status).toBe(401);
    }
  });

  test('the valid token initialises a session and lists tools', async () => {
    const fx = fixture();
    const app = build(config(), fx);
    const sessionId = await initialize(app);
    expect(await listTools(app, sessionId)).toEqual(['ping', 'block']);
    expect(app.stats().httpSessions).toBe(1);
  });

  test('a valid session id is not a substitute for the credential', async () => {
    const app = build(config(), fixture());
    const sessionId = await initialize(app);
    const res = await post(
      app,
      '/mcp',
      { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      { auth: null, sessionId },
    );
    expect(res.status).toBe(401);
    // GET (SSE channel) and DELETE (session close) are gated too.
    expect((await request(app, 'GET', '/mcp', { auth: null, sessionId })).status).toBe(401);
    expect((await request(app, 'DELETE', '/mcp', { auth: null, sessionId })).status).toBe(401);
    // The session survived the unauthenticated DELETE attempt.
    expect(app.stats().httpSessions).toBe(1);
  });

  test('the legacy transport is not a bypass: off by default (404), authenticated when enabled', async () => {
    const off = build(config(), fixture());
    expect((await request(off, 'GET', '/sse')).status).toBe(404);
    expect((await post(off, '/messages?sessionId=x', {})).status).toBe(404);

    const on = build(config({ AULA_MCP_LEGACY_SSE: '1' }), fixture());
    expect((await request(on, 'GET', '/sse', { auth: null })).status).toBe(401);
    expect((await post(on, '/messages?sessionId=x', {}, { auth: null })).status).toBe(401);
    expect((await post(on, '/messages?sessionId=x', {})).status).toBe(404); // authed, unknown session
  });

  test('unknown routes are 404 regardless of credentials', async () => {
    const app = build(config(), fixture());
    expect((await request(app, 'GET', '/', { auth: null })).status).toBe(404);
    expect((await request(app, 'GET', '/status', { auth: null })).status).toBe(404);
    expect((await request(app, 'GET', '/admin')).status).toBe(404);
  });

  test('AULA_MCP_AUTH=none on loopback serves unauthenticated clients', async () => {
    const cfg = loadServerConfig({ AULA_MCP_AUTH: 'none' });
    const app = build(cfg, fixture());
    const res = await post(app, '/mcp', INITIALIZE, { auth: null, host: '127.0.0.1:7878' });
    expect(res.status).toBe(200);
  });

  test('failed authentications are budgeted, and the budget never blocks the real client', async () => {
    const app = build(config({ AULA_MCP_AUTH_FAILURES_PER_MINUTE: '3' }), fixture());
    const bad = { auth: 'Bearer nope-nope-nope-nope-nope-nope-nope-nope-nope' };
    expect((await post(app, '/mcp', INITIALIZE, bad)).status).toBe(401);
    expect((await post(app, '/mcp', INITIALIZE, bad)).status).toBe(401);
    expect((await post(app, '/mcp', INITIALIZE, bad)).status).toBe(401);
    const throttled = await post(app, '/mcp', INITIALIZE, bad);
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get('retry-after')).toBeTruthy();
    // The legitimate client still gets in.
    await initialize(app);
    // The window resets with the clock.
    clock += 61_000;
    expect((await post(app, '/mcp', INITIALIZE, bad)).status).toBe(401);
  });

  test('the credential never appears in log output', async () => {
    const lines: string[] = [];
    const logger: Logger = {
      debug: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
      info: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
      warn: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
      error: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
    };
    const fx = fixture();
    const app = createHttpApp({
      config: config(),
      logger,
      createApp: fx.createApp,
      now: () => clock,
    });
    apps.push(app);
    await post(app, '/mcp', INITIALIZE, {
      auth: 'Bearer wrong-token-value-that-must-not-be-logged-000000',
    });
    await initialize(app);
    const joined = lines.join('\n');
    expect(joined).toContain('auth_failed');
    expect(joined).not.toContain(TOKEN);
    expect(joined).not.toContain('wrong-token-value');
  });
});

describe('HTTP MCP server: Host and Origin validation', () => {
  test('a Host that is not on the allow-list is 421 even with the right token', async () => {
    const fx = fixture();
    const app = build(config(), fx);
    for (const host of [
      'evil.example',
      'aula-mcp.example.com.evil.example',
      '203.0.113.7:7878',
      '',
    ]) {
      const res = await post(app, '/mcp', INITIALIZE, { host });
      expect([421, 400]).toContain(res.status);
    }
    expect(fx.created).toBe(0);
  });

  test('allowed hosts match case-insensitively, with or without an explicit port', async () => {
    const app = build(
      config({ AULA_MCP_ALLOWED_HOSTS: `${PUBLIC_HOST}, alt.example.com:8443` }),
      fixture(),
    );
    expect((await post(app, '/mcp', INITIALIZE, { host: 'AULA-MCP.EXAMPLE.COM' })).status).toBe(
      200,
    );
    expect((await post(app, '/mcp', INITIALIZE, { host: `${PUBLIC_HOST}:443` })).status).toBe(200);
    expect((await post(app, '/mcp', INITIALIZE, { host: 'alt.example.com:8443' })).status).toBe(
      200,
    );
    expect((await post(app, '/mcp', INITIALIZE, { host: 'alt.example.com' })).status).toBe(421);
    expect((await post(app, '/mcp', INITIALIZE, { host: 'alt.example.com:9999' })).status).toBe(
      421,
    );
  });

  test('loopback Host values are always accepted (local clients, container health checks)', async () => {
    const app = build(config(), fixture());
    for (const host of ['127.0.0.1:7878', 'localhost', '[::1]:7878']) {
      expect((await request(app, 'GET', '/healthz', { host, auth: null })).status).toBe(200);
    }
  });

  test('requests without an Origin header are served; browser origins must be allowed', async () => {
    const app = build(
      config({ AULA_MCP_ALLOWED_ORIGINS: 'https://assistant.example.com' }),
      fixture(),
    );
    expect((await post(app, '/mcp', INITIALIZE)).status).toBe(200);
    expect(
      (await post(app, '/mcp', INITIALIZE, { origin: 'https://assistant.example.com' })).status,
    ).toBe(200);
    // Same-origin pages served from the public host are fine too.
    expect((await post(app, '/mcp', INITIALIZE, { origin: `https://${PUBLIC_HOST}` })).status).toBe(
      200,
    );
    for (const origin of ['https://evil.example', 'null', 'http://localhost:3000', 'garbage']) {
      const res = await post(app, '/mcp', INITIALIZE, { origin });
      expect(res.status).toBe(403);
    }
  });

  test('Host/Origin checks run before authentication, so a rebound page learns nothing', async () => {
    const app = build(config(), fixture());
    const res = await post(app, '/mcp', INITIALIZE, { host: 'evil.example', auth: null });
    expect(res.status).toBe(421);
    expect(res.headers.get('www-authenticate')).toBeNull();
  });

  test('helpers', () => {
    expect(splitHostHeader('Example.com:443')).toEqual({ host: 'example.com', port: '443' });
    expect(splitHostHeader('[::1]:7878')).toEqual({ host: '[::1]', port: '7878' });
    expect(splitHostHeader('a b')).toBeNull();
    expect(splitHostHeader('host/path')).toBeNull();
    expect(splitHostHeader('user@host')).toBeNull();
    const cfg = { allowedHosts: ['aula.example.com'], allowedOrigins: [] as string[] };
    expect(hostHeaderAllowed('aula.example.com', cfg)).toBe(true);
    expect(hostHeaderAllowed('aula.example.com:443', cfg)).toBe(true);
    expect(hostHeaderAllowed('xaula.example.com', cfg)).toBe(false);
    expect(originAllowed('https://aula.example.com', cfg)).toBe(true);
    expect(originAllowed('https://aula.example.com:8443', cfg)).toBe(true);
    expect(originAllowed('https://other.example.com', cfg)).toBe(false);
    expect(originAllowed('null', cfg)).toBe(false);
    // Loopback is not implicitly trusted as an *origin* — only as a Host.
    expect(originAllowed('http://localhost:6274', cfg)).toBe(false);
    expect(originAllowed('http://127.0.0.1', cfg)).toBe(false);
    expect(
      originAllowed('http://localhost:6274', { ...cfg, allowedOrigins: ['http://localhost:6274'] }),
    ).toBe(true);
    const d = digest(TOKEN);
    expect(checkBearer(`Bearer ${TOKEN}`, d)).toBe('ok');
    expect(checkBearer(`bearer   ${TOKEN}`, d)).toBe('ok');
    expect(checkBearer(undefined, d)).toBe('missing');
    expect(checkBearer('Token abc', d)).toBe('malformed');
    expect(checkBearer('Bearer nope', d)).toBe('invalid');
  });
});

describe('HTTP MCP server: health probes', () => {
  test('/healthz needs no credential and carries no account data', async () => {
    const app = build(config(), fixture());
    const res = await request(app, 'GET', '/healthz', { auth: null });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, name: 'aula-mcp' });
    expect(res.headers.get('cache-control')).toBe('no-store');
  });

  test('/readyz distinguishes a live process from usable Aula credentials', async () => {
    let state: { ready: boolean; reason?: string } = { ready: false, reason: 'no_tokens' };
    const app = build(config(), fixture(), async () => state);
    let res = await request(app, 'GET', '/readyz', { auth: null });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ ready: false, reason: 'no_tokens' });
    state = { ready: true };
    res = await request(app, 'GET', '/readyz', { auth: null });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ready: true });
  });

  test('/readyz reports store_error instead of leaking a thrown message', async () => {
    const app = build(config(), fixture(), async () => {
      throw new Error('decrypt failed for /secret/path/tokens.json');
    });
    const res = await request(app, 'GET', '/readyz', { auth: null });
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain('/secret/path');
  });
});

describe('HTTP MCP server: request limits', () => {
  test('a body over AULA_MCP_MAX_BODY_BYTES is 413 whether or not Content-Length admits it', async () => {
    const app = build(config({ AULA_MCP_MAX_BODY_BYTES: '1024' }), fixture());
    const big = JSON.stringify({
      ...INITIALIZE,
      params: { ...INITIALIZE.params, pad: 'x'.repeat(4096) },
    });
    const res = await post(app, '/mcp', big);
    expect(res.status).toBe(413);

    // Chunked body with no Content-Length: the byte counter, not the header, decides.
    const chunks = [
      new TextEncoder().encode('{"a":"'),
      new TextEncoder().encode('y'.repeat(2000)),
      new TextEncoder().encode('"}'),
    ];
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        const next = chunks.shift();
        if (next) controller.enqueue(next);
        else controller.close();
      },
    });
    const streamed = new Request(`https://${PUBLIC_HOST}/mcp`, {
      method: 'POST',
      headers: headers({}),
      body: stream,
      duplex: 'half',
    });
    expect(await readBoundedRequest(streamed, 1024)).toBeNull();
    const small = new Request(`https://${PUBLIC_HOST}/mcp`, {
      method: 'POST',
      headers: headers({}),
      body: '{"ok":1}',
    });
    const bounded = await readBoundedRequest(small, 1024);
    expect(await bounded?.text()).toBe('{"ok":1}');
  });

  test('the global request budget answers 429 with Retry-After once exhausted', async () => {
    const app = build(config({ AULA_MCP_REQUESTS_PER_MINUTE: '3' }), fixture());
    for (let i = 0; i < 3; i++) {
      expect((await request(app, 'GET', '/healthz', { auth: null })).status).toBe(200);
    }
    const limited = await request(app, 'GET', '/healthz', { auth: null });
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
    clock += 60_000;
    expect((await request(app, 'GET', '/healthz', { auth: null })).status).toBe(200);
  });

  test('in-flight POSTs are capped: the excess request gets 503 immediately', async () => {
    const fx = fixture();
    const app = build(config({ AULA_MCP_MAX_CONCURRENT_REQUESTS: '1' }), fx);
    const sessionId = await initialize(app);
    const blocked = post(
      app,
      '/mcp',
      { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'block', arguments: {} } },
      { sessionId },
    );
    // Give the first request a tick to enter the handler.
    await new Promise((r) => setTimeout(r, 20));
    const rejected = await post(
      app,
      '/mcp',
      { jsonrpc: '2.0', id: 8, method: 'tools/list' },
      { sessionId },
    );
    expect(rejected.status).toBe(503);
    expect(await rejected.json()).toEqual({ error: 'too_many_concurrent_requests' });
    fx.release();
    const done = await blocked;
    expect(done.status).toBe(200);
    expect(app.stats().inFlight).toBe(0);
  });

  test('new sessions beyond AULA_MCP_HTTP_MAX_SESSIONS are refused with 503', async () => {
    const app = build(config({ AULA_MCP_HTTP_MAX_SESSIONS: '1' }), fixture());
    await initialize(app);
    const res = await post(app, '/mcp', INITIALIZE);
    expect(res.status).toBe(503);
  });
});

describe('HTTP MCP server: session lifecycle disposes the AulaContext', () => {
  test('DELETE /mcp closes the session and disposes its context', async () => {
    const fx = fixture();
    const app = build(config(), fx);
    const sessionId = await initialize(app);
    expect(fx.disposed).toEqual([]);
    const res = await request(app, 'DELETE', '/mcp', { sessionId });
    expect(res.status).toBe(200);
    await new Promise((r) => setTimeout(r, 10));
    expect(fx.disposed).toEqual(['ctx-1']);
    expect(app.stats().httpSessions).toBe(0);
    // The old id is gone for good.
    const gone = await post(
      app,
      '/mcp',
      { jsonrpc: '2.0', id: 1, method: 'tools/list' },
      { sessionId },
    );
    expect(gone.status).toBe(404);
  });

  test('idle sessions are evicted and disposed by the sweeper', async () => {
    const fx = fixture();
    const app = build(config({ AULA_MCP_HTTP_IDLE_MS: '5000' }), fx);
    await initialize(app);
    await initialize(app);
    expect(app.stats().httpSessions).toBe(2);
    app.sweep(clock + 4_000);
    expect(app.stats().httpSessions).toBe(2);
    app.sweep(clock + 5_001);
    await new Promise((r) => setTimeout(r, 10));
    expect(app.stats().httpSessions).toBe(0);
    expect(fx.disposed.sort()).toEqual(['ctx-1', 'ctx-2']);
  });

  test('a failed initialize leaves nothing behind', async () => {
    const fx = fixture();
    const app = build(config(), fx);
    const res = await post(app, '/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(res.status).toBe(400);
    await new Promise((r) => setTimeout(r, 10));
    expect(app.stats().httpSessions).toBe(0);
    expect(fx.disposed).toEqual(['ctx-1']);
  });

  test('shutdown closes every session', async () => {
    const fx = fixture();
    const app = build(config(), fx);
    await initialize(app);
    await initialize(app);
    await app.shutdown();
    expect(app.stats().httpSessions).toBe(0);
    expect(fx.disposed.sort()).toEqual(['ctx-1', 'ctx-2']);
  });

  test('legacy SSE sessions are disposed when evicted', async () => {
    const fx = fixture();
    const app = build(config({ AULA_MCP_LEGACY_SSE: '1', AULA_MCP_SSE_IDLE_MS: '5000' }), fx);
    const controller = new AbortController();
    const res = await app.fetch(
      new Request(`https://${PUBLIC_HOST}/sse`, {
        headers: {
          host: PUBLIC_HOST,
          authorization: `Bearer ${TOKEN}`,
          accept: 'text/event-stream',
        },
        signal: controller.signal,
      }),
    );
    expect(res.status).toBe(200);
    const reader = res.body?.getReader();
    const first = await reader?.read();
    expect(new TextDecoder().decode(first?.value)).toContain('event: endpoint');
    expect(app.stats().sseSessions).toBe(1);
    app.sweep(clock + 5_001);
    await new Promise((r) => setTimeout(r, 20));
    expect(app.stats().sseSessions).toBe(0);
    expect(fx.disposed).toEqual(['ctx-1']);
    controller.abort();
  });
});
