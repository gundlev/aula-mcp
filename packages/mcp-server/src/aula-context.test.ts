/**
 * Regression tests for the token-refresh races the audit reproduced against
 * AulaContext (finding 7): three parallel `getClient()` calls on a warmed
 * context with an expired token issued three refresh requests, separate MCP
 * sessions refreshed independently, and disposed sessions leaked their file
 * watchers. Synthetic tokens and a fake HTTP client throughout — nothing
 * here talks to Aula.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type AulaHttpClient,
  type AulaResponse,
  type AulaTokens,
  EncryptedFileTokenStore,
  resetTokenRefreshers,
  type StoredTokenRecord,
} from '@aula-mcp/aula-auth';
import { AulaContext } from './aula-context.ts';

const nowSec = () => Math.floor(Date.now() / 1000);

function tokens(overrides: Partial<AulaTokens> = {}): AulaTokens {
  return {
    access_token: 'SYNTH-AT-0',
    refresh_token: 'SYNTH-RT-0',
    token_type: 'Bearer',
    expires_in: 3600,
    expires_at: nowSec() + 3600,
    obtained_at: nowSec(),
    ...overrides,
  };
}

function record(t: AulaTokens): StoredTokenRecord {
  return { version: 1, username: 'synthetic-user', tokens: t, saved_at: nowSec() };
}

/** Access token that is already inside the 60 s refresh buffer. */
const expiredTokens = () => tokens({ expires_at: nowSec() + 10 });

/** Fake token endpoint: counts refreshes, can stall or fail on demand. */
class FakeHttp {
  calls: string[] = [];
  delayMs = 0;
  failNext = 0;
  private counter = 0;
  async request(url: string, options: { body?: unknown } = {}): Promise<AulaResponse> {
    const body = options.body instanceof URLSearchParams ? options.body : new URLSearchParams();
    this.calls.push(body.get('refresh_token') ?? '');
    if (this.delayMs) await new Promise((r) => setTimeout(r, this.delayMs));
    if (this.failNext > 0) {
      this.failNext--;
      return { status: 500, headers: new Headers(), body: 'synthetic outage', url };
    }
    this.counter++;
    return {
      status: 200,
      headers: new Headers(),
      body: JSON.stringify({
        access_token: `SYNTH-AT-${this.counter}`,
        refresh_token: `SYNTH-RT-${this.counter}`,
        token_type: 'Bearer',
        expires_in: 3600,
      }),
      url,
    };
  }
}

const asHttp = (fake: FakeHttp) => fake as unknown as AulaHttpClient;

let dir: string;
let fake: FakeHttp;
const contexts: AulaContext[] = [];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aula-context-'));
  fake = new FakeHttp();
  resetTokenRefreshers();
});

afterEach(async () => {
  for (const ctx of contexts.splice(0)) ctx.dispose();
  await rm(dir, { recursive: true, force: true });
});

function store(): EncryptedFileTokenStore {
  return new EncryptedFileTokenStore({
    filePath: join(dir, 'tokens.json'),
    keyFilePath: join(dir, '.key'),
    envVarName: 'AULA_TEST_UNSET_KEY_VAR',
  });
}

/** Each call builds a fresh store object, like each MCP session does. */
function context(): AulaContext {
  const ctx = new AulaContext({
    store: store(),
    http: asHttp(fake),
    recheckIntervalMs: 0,
  });
  contexts.push(ctx);
  return ctx;
}

describe('AulaContext token refresh', () => {
  test('parallel getClient() calls on an expired token issue exactly one refresh', async () => {
    await store().save(record(expiredTokens()));
    fake.delayMs = 30;
    const ctx = context();
    // Warm the context the way a first tool call would (still expired, so it
    // refreshes once here) …
    const warm = await ctx.getClient();
    expect(fake.calls).toEqual(['SYNTH-RT-0']);

    // … then expire the tokens again behind its back and hit it in parallel.
    await store().save(
      record(
        tokens({
          access_token: 'SYNTH-AT-1',
          refresh_token: 'SYNTH-RT-1',
          expires_at: nowSec() + 5,
        }),
      ),
    );
    const clients = await Promise.all([ctx.getClient(), ctx.getClient(), ctx.getClient()]);

    expect(fake.calls).toEqual(['SYNTH-RT-0', 'SYNTH-RT-1']);
    expect(new Set(clients).size).toBe(1);
    expect(clients[0]).not.toBe(warm);
    expect(ctx.record?.tokens.access_token).toBe('SYNTH-AT-2');
  });

  test('separate sessions on the same token file share one in-flight refresh', async () => {
    await store().save(record(expiredTokens()));
    fake.delayMs = 30;
    const [a, b, c] = [context(), context(), context()];
    await Promise.all([a.getClient(), b.getClient(), c.getClient()]);
    expect(fake.calls).toEqual(['SYNTH-RT-0']);
    expect(a.record?.tokens.access_token).toBe('SYNTH-AT-1');
    expect(b.record?.tokens.access_token).toBe('SYNTH-AT-1');
    expect(c.record?.tokens.access_token).toBe('SYNTH-AT-1');
    // The refreshed tokens were persisted once for everyone.
    expect((await store().load())?.tokens.refresh_token).toBe('SYNTH-RT-1');
  });

  test('valid tokens never trigger a refresh and reuse the same client', async () => {
    await store().save(record(tokens()));
    const ctx = context();
    const first = await ctx.getClient();
    const second = await ctx.getClient();
    expect(first).toBe(second);
    expect(fake.calls).toEqual([]);
  });

  test('an out-of-band login rotates the client and drops the widget-token manager', async () => {
    await store().save(record(tokens()));
    const ctx = context();
    const client1 = await ctx.getClient();
    const widgets1 = await ctx.getWidgetManager();
    expect(await ctx.getWidgetManager()).toBe(widgets1);

    // `aula login` on the CLI writes new tokens; with recheckIntervalMs 0 the
    // refresher notices on the next call without needing the file watcher.
    await store().save(
      record(tokens({ access_token: 'SYNTH-AT-NEW', refresh_token: 'SYNTH-RT-NEW' })),
    );
    const client2 = await ctx.getClient();
    const widgets2 = await ctx.getWidgetManager();

    expect(client2).not.toBe(client1);
    expect(widgets2).not.toBe(widgets1);
    expect(ctx.record?.tokens.access_token).toBe('SYNTH-AT-NEW');
    expect(fake.calls).toEqual([]);
  });

  test('a failed refresh is not cached: the next call retries and recovers', async () => {
    await store().save(record(expiredTokens()));
    fake.failNext = 1;
    const ctx = context();
    await expect(ctx.getClient()).rejects.toThrow();
    expect(fake.calls).toHaveLength(1);

    const client = await ctx.getClient();
    expect(client).toBeDefined();
    expect(fake.calls).toHaveLength(2);
    expect(ctx.record?.tokens.access_token).toBe('SYNTH-AT-1');
  });

  test('tokens removed by a logout are not resurrected from a stale cache', async () => {
    await store().save(record(tokens()));
    const ctx = context();
    await ctx.getClient();
    await store().clear();
    await expect(ctx.getClient()).rejects.toThrow(/aula login/);
    expect(fake.calls).toEqual([]);
  });

  test('dispose() stops the context: getClient() refuses and nothing is cached', async () => {
    await store().save(record(tokens()));
    const ctx = context();
    await ctx.getClient();
    ctx.dispose();
    expect(ctx.record).toBeUndefined();
    await expect(ctx.getClient()).rejects.toThrow(/disposed/);
    // Disposing twice is harmless.
    ctx.dispose();
  });
});

describe('AulaContext readiness (/readyz)', () => {
  test('no tokens on disk → not ready, no_tokens', async () => {
    const ctx = context();
    expect(await ctx.readiness()).toEqual({ ready: false, reason: 'no_tokens' });
  });

  test('valid tokens → ready without touching the token endpoint', async () => {
    await store().save(record(tokens()));
    const ctx = context();
    expect(await ctx.readiness()).toEqual({ ready: true });
    expect(fake.calls).toEqual([]);
  });

  test('expired tokens with a working refresh → ready (and the refresh is shared)', async () => {
    await store().save(record(expiredTokens()));
    const ctx = context();
    expect(await ctx.readiness()).toEqual({ ready: true });
    expect(fake.calls).toHaveLength(1);
    // The refreshed record is what tool calls now get, with no second refresh.
    await ctx.getClient();
    expect(fake.calls).toHaveLength(1);
  });

  test('expired tokens with a failing refresh → refresh_failing, backing off instead of retrying', async () => {
    await store().save(record(expiredTokens()));
    fake.failNext = 5;
    const ctx = context();
    expect(await ctx.readiness()).toEqual({ ready: false, reason: 'refresh_failing' });
    expect(await ctx.readiness()).toEqual({ ready: false, reason: 'refresh_failing' });
    expect(fake.calls).toHaveLength(1);
  });

  test('an unreadable token file → store_error, never a throw', async () => {
    await store().save(record(tokens()));
    await writeFile(join(dir, 'tokens.json'), 'not an envelope', { mode: 0o600 });
    const ctx = context();
    expect(await ctx.readiness()).toEqual({ ready: false, reason: 'store_error' });
  });

  test('the report never contains account data', async () => {
    await store().save(record(tokens({ access_token: 'SYNTH-AT-SECRET' })));
    const ctx = context();
    const text = JSON.stringify(await ctx.readiness());
    expect(text).not.toContain('synthetic-user');
    expect(text).not.toContain('SYNTH-AT-SECRET');
    expect(text).not.toContain('expires');
  });
});
