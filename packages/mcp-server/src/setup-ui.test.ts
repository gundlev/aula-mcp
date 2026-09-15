/**
 * Access-control and cleanup tests for the setup/login UI (audit finding 5).
 *
 * The audit read a synthetic username from unauthenticated GET /status and
 * logged the household out with a cross-origin POST /logout. Every route is
 * gated here; state-changing calls additionally need the CSRF header. Login
 * sessions are dropped on a timer even when no event stream attaches.
 *
 * MitID itself is never invoked — tests inject a fake runner.
 */

import { afterEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import type { Logger, StoredTokenRecord, TokenStore } from '@aula-mcp/aula-auth';
import {
  authorise,
  createSetupApp,
  CSRF_HEADER,
  CSRF_HEADER_VALUE,
  DEFAULT_HA_INGRESS_PROXY,
  loadSetupAuth,
  type LoginRunner,
  normaliseAddress,
  SetupConfigError,
  type SetupApp,
} from './setup-ui.ts';

class MemoryStore implements TokenStore {
  private record: StoredTokenRecord | null = null;
  async load(): Promise<StoredTokenRecord | null> {
    return this.record;
  }
  async save(record: StoredTokenRecord): Promise<void> {
    this.record = record;
  }
  async clear(): Promise<void> {
    this.record = null;
  }
}

const SAMPLE_RECORD: StoredTokenRecord = {
  version: 1,
  username: 'synthetic-parent',
  tokens: {
    access_token: 'SYNTH-AT',
    refresh_token: 'SYNTH-RT',
    token_type: 'Bearer',
    expires_in: 3600,
    expires_at: Math.floor(Date.now() / 1000) + 3600,
    obtained_at: Math.floor(Date.now() / 1000),
  },
  saved_at: Math.floor(Date.now() / 1000),
};

const PASSWORD = 'synthetic-setup-password';
const PASSWORD_DIGEST = createHash('sha256').update(PASSWORD, 'utf8').digest();

const CSRF = { [CSRF_HEADER]: CSRF_HEADER_VALUE, 'content-type': 'application/json' };

const apps: SetupApp[] = [];

function app(opts: Parameters<typeof createSetupApp>[0] = {}): SetupApp {
  const created = createSetupApp({
    store: opts.store ?? new MemoryStore(),
    auth: opts.auth ?? { mode: 'none' },
    ...opts,
  });
  apps.push(created);
  return created;
}

afterEach(async () => {
  for (const a of apps.splice(0)) await a.close();
});

function get(a: SetupApp, path: string, init: RequestInit & { peer?: string } = {}): Promise<Response> {
  const { peer, ...rest } = init;
  return Promise.resolve(a.fetch(new Request(`http://test${path}`, rest), { remoteAddress: peer ?? null }));
}

function post(
  a: SetupApp,
  path: string,
  body: unknown,
  init: RequestInit & { peer?: string; csrf?: boolean } = {},
): Promise<Response> {
  const { peer, csrf = true, headers, ...rest } = init;
  return Promise.resolve(
    a.fetch(
      new Request(`http://test${path}`, {
        method: 'POST',
        headers: { ...(csrf ? CSRF : { 'content-type': 'application/json' }), ...headers },
        body: typeof body === 'string' ? body : JSON.stringify(body),
        ...rest,
      }),
      { remoteAddress: peer ?? null },
    ),
  );
}

const hang: LoginRunner = (session) =>
  new Promise<void>((resolve) => {
    session.abort.signal.addEventListener('abort', () => {
      session.terminal = { event: 'error', data: JSON.stringify({ message: 'aborted' }) };
      session.signalDone();
      resolve();
    });
  });

describe('loadSetupAuth — fail closed', () => {
  test('unset mode is an error (standalone deployments leave the UI off)', () => {
    expect(() => loadSetupAuth({}, '127.0.0.1')).toThrow(SetupConfigError);
    expect(() => loadSetupAuth({}, '127.0.0.1')).toThrow(/AULA_MCP_SETUP_AUTH is not set/);
  });

  test('none is only allowed on loopback', () => {
    expect(loadSetupAuth({ AULA_MCP_SETUP_AUTH: 'none' }, '127.0.0.1')).toEqual({ mode: 'none' });
    expect(() => loadSetupAuth({ AULA_MCP_SETUP_AUTH: 'none' }, '0.0.0.0')).toThrow(/loopback/);
  });

  test('password requires a long enough secret', () => {
    expect(() => loadSetupAuth({ AULA_MCP_SETUP_AUTH: 'password' }, '0.0.0.0')).toThrow(/PASSWORD/);
    expect(() =>
      loadSetupAuth({ AULA_MCP_SETUP_AUTH: 'password', AULA_MCP_SETUP_PASSWORD: 'short' }, '0.0.0.0'),
    ).toThrow(/at least/);
    const cfg = loadSetupAuth(
      { AULA_MCP_SETUP_AUTH: 'password', AULA_MCP_SETUP_PASSWORD: PASSWORD },
      '0.0.0.0',
    );
    expect(cfg.mode).toBe('password');
  });

  test('ingress defaults to the HA Supervisor proxy address', () => {
    expect(loadSetupAuth({ AULA_MCP_SETUP_AUTH: 'ingress' }, '0.0.0.0')).toEqual({
      mode: 'ingress',
      trustedProxies: [DEFAULT_HA_INGRESS_PROXY],
    });
  });

  test('unknown modes are rejected', () => {
    expect(() => loadSetupAuth({ AULA_MCP_SETUP_AUTH: 'bearer' }, '127.0.0.1')).toThrow(/not understood/);
  });
});

describe('authorise', () => {
  test('ingress trusts only the TCP peer, never a forwarded header', () => {
    const auth = { mode: 'ingress' as const, trustedProxies: [DEFAULT_HA_INGRESS_PROXY] };
    const req = new Request('http://test/status', { headers: { 'x-forwarded-for': DEFAULT_HA_INGRESS_PROXY } });
    expect(authorise(auth, req, {})).toBe('untrusted_peer');
    expect(authorise(auth, req, { remoteAddress: '10.0.0.9' })).toBe('untrusted_peer');
    expect(authorise(auth, req, { remoteAddress: DEFAULT_HA_INGRESS_PROXY })).toBe('ok');
    expect(authorise(auth, req, { remoteAddress: `::ffff:${DEFAULT_HA_INGRESS_PROXY}` })).toBe('ok');
    expect(normaliseAddress(`::ffff:${DEFAULT_HA_INGRESS_PROXY}`)).toBe(DEFAULT_HA_INGRESS_PROXY);
  });

  test('password is constant-time Basic, any username', () => {
    const auth = { mode: 'password' as const, passwordDigest: PASSWORD_DIGEST };
    const req = (header?: string) =>
      new Request('http://test/status', header ? { headers: { authorization: header } } : {});
    expect(authorise(auth, req(), {})).toBe('password_required');
    expect(authorise(auth, req(`Basic ${Buffer.from(`admin:${PASSWORD}`).toString('base64')}`), {})).toBe('ok');
    expect(authorise(auth, req(`Basic ${Buffer.from(`x:${PASSWORD}`).toString('base64')}`), {})).toBe('ok');
    expect(authorise(auth, req(`Basic ${Buffer.from('x:wrong-password-xx').toString('base64')}`), {})).toBe(
      'password_invalid',
    );
    expect(authorise(auth, req(`Bearer ${PASSWORD}`), {})).toBe('password_required');
  });
});

describe('setup UI: ingress and password gates', () => {
  test('ingress mode hides every route from a LAN peer, including /status and /logout', async () => {
    const store = new MemoryStore();
    await store.save(SAMPLE_RECORD);
    const ui = app({ store, auth: { mode: 'ingress', trustedProxies: [DEFAULT_HA_INGRESS_PROXY] } });

    for (const [method, path] of [
      ['GET', '/'],
      ['GET', '/status'],
      ['POST', '/logout'],
      ['POST', '/login/start'],
    ] as const) {
      const res =
        method === 'GET'
          ? await get(ui, path, { peer: '192.168.1.50' })
          : await post(ui, path, { username: 'x' }, { peer: '192.168.1.50' });
      expect(res.status).toBe(403);
      expect(await res.text()).not.toContain('synthetic-parent');
    }

    const ok = await get(ui, '/status', { peer: DEFAULT_HA_INGRESS_PROXY });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toMatchObject({ logged_in: true, username: 'synthetic-parent' });
  });

  test('password mode challenges unauthenticated clients and never discloses status', async () => {
    const store = new MemoryStore();
    await store.save(SAMPLE_RECORD);
    const ui = app({ store, auth: { mode: 'password', passwordDigest: PASSWORD_DIGEST } });
    const res = await get(ui, '/status');
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('Basic');
    expect(await res.text()).not.toContain('synthetic-parent');

    const authed = await get(ui, '/status', {
      headers: { authorization: `Basic ${Buffer.from(`u:${PASSWORD}`).toString('base64')}` },
    });
    expect(authed.status).toBe(200);
  });
});

describe('setup UI: CSRF and origin', () => {
  test('logout without the CSRF header is refused and the store is untouched', async () => {
    const store = new MemoryStore();
    await store.save(SAMPLE_RECORD);
    const ui = app({ store });
    const res = await post(ui, '/logout', {}, { csrf: false });
    expect(res.status).toBe(403);
    expect(await store.load()).not.toBeNull();
  });

  test('a cross-site Sec-Fetch-Site is refused even with the CSRF header', async () => {
    const store = new MemoryStore();
    await store.save(SAMPLE_RECORD);
    const ui = app({ store });
    const res = await post(ui, '/logout', {}, { headers: { 'sec-fetch-site': 'cross-site' } });
    expect(res.status).toBe(403);
    expect(await store.load()).not.toBeNull();
  });

  test('logout with the CSRF header clears the store', async () => {
    const store = new MemoryStore();
    await store.save(SAMPLE_RECORD);
    const ui = app({ store });
    const res = await post(ui, '/logout', {});
    expect(res.status).toBe(200);
    expect(await store.load()).toBeNull();
  });
});

describe('setup UI: routes and input', () => {
  test('GET / serves the login HTML with the CSRF header wired in', async () => {
    const ui = app();
    const res = await get(ui, '/');
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('EventSource');
    expect(body).toContain(CSRF_HEADER_VALUE);
    expect(body).toContain('login/start');
  });

  test('GET /status reports empty vs logged-in without leaking tokens', async () => {
    const empty = app();
    expect(await (await get(empty, '/status')).json()).toEqual({ logged_in: false });

    const store = new MemoryStore();
    await store.save(SAMPLE_RECORD);
    const logged = app({ store });
    const body = (await (await get(logged, '/status')).json()) as Record<string, unknown>;
    expect(body.logged_in).toBe(true);
    expect(body.username).toBe('synthetic-parent');
    expect(JSON.stringify(body)).not.toContain('SYNTH-AT');
  });

  test('POST /login/start rejects missing, oversized and whitespace usernames', async () => {
    const ui = app({ runLogin: hang });
    expect((await post(ui, '/login/start', {})).status).toBe(400);
    expect((await post(ui, '/login/start', { username: 'a'.repeat(200) })).status).toBe(400);
    expect((await post(ui, '/login/start', { username: 'two words' })).status).toBe(400);
    expect((await post(ui, '/login/start', '{not json', { csrf: true })).status).toBe(400);
  });

  test('a second concurrent login is 409; bursts are 429', async () => {
    const ui = app({
      runLogin: hang,
      limits: { maxConcurrentLogins: 1, loginStartsPerWindow: 2, loginWindowMs: 60_000 },
    });
    expect((await post(ui, '/login/start', { username: 'one' })).status).toBe(200);
    expect((await post(ui, '/login/start', { username: 'two' })).status).toBe(409);

    const bursty = app({
      runLogin: hang,
      limits: { maxConcurrentLogins: 8, loginStartsPerWindow: 2, loginWindowMs: 60_000 },
    });
    expect((await post(bursty, '/login/start', { username: 'a' })).status).toBe(200);
    expect((await post(bursty, '/login/start', { username: 'b' })).status).toBe(200);
    expect((await post(bursty, '/login/start', { username: 'c' })).status).toBe(429);
  });

  test('GET /login/events and POST /login/identity validate the session id', async () => {
    const ui = app();
    expect((await get(ui, '/login/events')).status).toBe(400);
    expect((await get(ui, '/login/events?sessionId=not-a-uuid')).status).toBe(400);
    expect((await get(ui, '/login/events?sessionId=00000000-0000-0000-0000-000000000000')).status).toBe(404);
    expect((await post(ui, '/login/identity', { index: 1 })).status).toBe(400);
    expect((await post(ui, '/login/identity?sessionId=00000000-0000-0000-0000-000000000000', { index: 1 })).status).toBe(
      404,
    );
  });
});

describe('setup UI: session cleanup without an event stream', () => {
  test('a finished login is dropped after the retention window even if nobody subscribed', async () => {
    const runner: LoginRunner = async (session) => {
      session.terminal = { event: 'success', data: JSON.stringify({ identityName: null, expiresInSec: 1 }) };
      session.signalDone();
    };
    const ui = app({ runLogin: runner, limits: { sessionRetentionMs: 30 } });
    const res = await post(ui, '/login/start', { username: 'alice' });
    expect(res.status).toBe(200);
    expect(ui.stats().loginSessions).toBe(1);
    await new Promise((r) => setTimeout(r, 80));
    expect(ui.stats().loginSessions).toBe(0);
  });

  test('close() aborts an in-flight login that never attached a stream', async () => {
    const ui = app({ runLogin: hang });
    await post(ui, '/login/start', { username: 'alice' });
    expect(ui.stats().activeLogins).toBe(1);
    await ui.close();
    expect(ui.stats().loginSessions).toBe(0);
    expect(ui.stats().activeLogins).toBe(0);
  });

  test('the password is never written to a log line', async () => {
    const lines: string[] = [];
    const logger: Logger = {
      debug: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
      info: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
      warn: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
      error: (m, meta) => lines.push(`${m} ${JSON.stringify(meta ?? {})}`),
    };
    const ui = app({
      logger,
      auth: { mode: 'password', passwordDigest: PASSWORD_DIGEST },
    });
    await get(ui, '/status', { headers: { authorization: `Basic ${Buffer.from(`u:${PASSWORD}`).toString('base64')}` } });
    await get(ui, '/status');
    const joined = lines.join('\n');
    expect(joined).not.toContain(PASSWORD);
    expect(joined).not.toContain('synthetic-setup');
  });
});
