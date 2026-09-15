/**
 * Security regression tests for token refresh races and credential writes
 * (audit finding 7). The audit observed three simultaneous callers issuing
 * three refresh requests with the same refresh token, plus non-atomic token
 * file writes. Every assertion here uses synthetic tokens and a fake HTTP
 * client — no network.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtemp, open, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AulaTokens } from './aula-oauth.ts';
import { acquireFileLock, FileLockError, withFileLock } from './file-lock.ts';
import type { AulaHttpClient, AulaResponse } from './http.ts';
import { getTokenRefresher, resetTokenRefreshers, TokenRefresher } from './token-refresh.ts';
import {
  EncryptedFileTokenStore,
  readKeyFile,
  type StoredTokenRecord,
  TokenStoreError,
  withFreshTokens,
  writeFileAtomic,
  writeKeyFile,
} from './token-store.ts';

const now = () => Math.floor(Date.now() / 1000);

function tokens(overrides: Partial<AulaTokens> = {}): AulaTokens {
  return {
    access_token: 'SYNTH-AT-0',
    refresh_token: 'SYNTH-RT-0',
    token_type: 'Bearer',
    expires_in: 3600,
    expires_at: now() + 3600,
    obtained_at: now(),
    ...overrides,
  };
}

function record(t: AulaTokens): StoredTokenRecord {
  return { version: 1, username: 'synthetic-user', tokens: t, saved_at: now() };
}

/**
 * Fake AulaHttpClient: every POST to the token endpoint hands out a new
 * access token and (rotated) refresh token, optionally after a delay or
 * with a scripted failure. Counts calls so the tests can assert "exactly
 * one refresh happened".
 */
class FakeHttp {
  calls: string[] = [];
  delayMs = 0;
  failNext = 0;
  private counter = 0;
  async request(_url: string, options: { body?: unknown } = {}): Promise<AulaResponse> {
    const body = options.body instanceof URLSearchParams ? options.body : new URLSearchParams();
    this.calls.push(body.get('refresh_token') ?? '');
    if (this.delayMs) await new Promise((r) => setTimeout(r, this.delayMs));
    if (this.failNext > 0) {
      this.failNext--;
      return { status: 500, headers: new Headers(), body: 'synthetic outage', url: _url };
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
      url: _url,
    };
  }
}

const asHttp = (fake: FakeHttp) => fake as unknown as AulaHttpClient;

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aula-refresh-'));
  resetTokenRefreshers();
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function fileStore(): EncryptedFileTokenStore {
  return new EncryptedFileTokenStore({
    filePath: join(dir, 'tokens.json'),
    keyFilePath: join(dir, '.key'),
    envVarName: 'AULA_TEST_UNSET_KEY_VAR',
  });
}

describe('atomic, owner-only credential writes', () => {
  test('tokens.json and .key are created 0600 in a 0700 directory with no temp files left', async () => {
    const store = new EncryptedFileTokenStore({
      filePath: join(dir, 'nested', 'tokens.json'),
      keyFilePath: join(dir, 'nested', '.key'),
      envVarName: 'AULA_TEST_UNSET_KEY_VAR',
    });
    await store.save(record(tokens()));
    expect((await stat(join(dir, 'nested', 'tokens.json'))).mode & 0o777).toBe(0o600);
    expect((await stat(join(dir, 'nested', '.key'))).mode & 0o777).toBe(0o600);
    expect((await stat(join(dir, 'nested'))).mode & 0o777).toBe(0o700);
    const leftovers = (await readdir(join(dir, 'nested'))).filter((n) => n.endsWith('.tmp'));
    expect(leftovers).toEqual([]);
  });

  test('overwriting a world-readable file leaves it owner-only and never torn', async () => {
    const path = join(dir, 'tokens.json');
    await writeFile(path, '{"old":true}', { mode: 0o644 });
    const store = fileStore();
    await store.save(record(tokens()));
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    // Many overlapping saves: whatever wins, the file is always a complete envelope.
    await Promise.all(
      Array.from({ length: 12 }, (_, i) =>
        store.save(record(tokens({ access_token: `SYNTH-AT-${i}` }))),
      ),
    );
    const envelope = JSON.parse(await readFile(path, 'utf8')) as { alg: string };
    expect(envelope.alg).toBe('aes-256-gcm');
    expect(await store.load()).not.toBeNull();
  });

  test('writeFileAtomic refuses to clobber via a half-written temp file', async () => {
    const path = join(dir, 'blob');
    await writeFileAtomic(path, 'one');
    await writeFileAtomic(path, 'two');
    expect(await readFile(path, 'utf8')).toBe('two');
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  test('readKeyFile reports a missing bundle key instead of returning garbage', async () => {
    await expect(readKeyFile(join(dir, 'missing.key'))).rejects.toBeInstanceOf(TokenStoreError);
    await writeKeyFile(join(dir, 'a.key'), 'ab'.repeat(32));
    expect((await readKeyFile(join(dir, 'a.key'))).length).toBe(32);
    expect((await stat(join(dir, 'a.key'))).mode & 0o777).toBe(0o600);
  });
});

describe('withFreshTokens: cross-process lock and stale writes', () => {
  test('two independent stores on one file refresh exactly once', async () => {
    const seed = fileStore();
    await seed.save(record(tokens({ expires_at: now() - 10 })));
    const http = new FakeHttp();
    http.delayMs = 30;
    // Two MCP sessions (or a server + CLI) each construct their own store.
    const [a, b] = await Promise.all([
      withFreshTokens({ store: fileStore(), http: asHttp(http) }),
      withFreshTokens({ store: fileStore(), http: asHttp(http) }),
    ]);
    expect(http.calls).toEqual(['SYNTH-RT-0']);
    expect(a.tokens.access_token).toBe('SYNTH-AT-1');
    expect(b.tokens.access_token).toBe('SYNTH-AT-1');
    expect((await fileStore().load())?.tokens.refresh_token).toBe('SYNTH-RT-1');
    // The lock is released afterwards.
    await expect(stat(join(dir, 'tokens.json.lock'))).rejects.toThrow();
  });

  test('a newer login written during the refresh is not clobbered', async () => {
    const store = fileStore();
    await store.save(record(tokens({ expires_at: now() - 10 })));
    const http = new FakeHttp();
    http.delayMs = 50;
    const refreshing = withFreshTokens({ store, http: asHttp(http) });
    // Meanwhile the user runs `aula login`, producing fresh, valid tokens.
    await new Promise((r) => setTimeout(r, 10));
    await store.save(
      record(tokens({ access_token: 'SYNTH-AT-LOGIN', refresh_token: 'SYNTH-RT-LOGIN' })),
    );
    const result = await refreshing;
    expect(result.tokens.access_token).toBe('SYNTH-AT-LOGIN');
    expect((await store.load())?.tokens.refresh_token).toBe('SYNTH-RT-LOGIN');
  });

  test('a logout during the refresh wins: nothing is resurrected on disk', async () => {
    const store = fileStore();
    await store.save(record(tokens({ expires_at: now() - 10 })));
    const http = new FakeHttp();
    http.delayMs = 50;
    const refreshing = withFreshTokens({ store, http: asHttp(http) });
    await new Promise((r) => setTimeout(r, 10));
    await store.clear();
    await expect(refreshing).rejects.toBeInstanceOf(TokenStoreError);
    expect(await store.load()).toBeNull();
  });

  test('a failed refresh leaves the old record intact and the next attempt succeeds', async () => {
    const store = fileStore();
    await store.save(record(tokens({ expires_at: now() - 10 })));
    const http = new FakeHttp();
    http.failNext = 1;
    await expect(withFreshTokens({ store, http: asHttp(http) })).rejects.toThrow(/status 500/);
    expect((await store.load())?.tokens.refresh_token).toBe('SYNTH-RT-0');
    const ok = await withFreshTokens({ store, http: asHttp(http) });
    expect(ok.tokens.access_token).toBe('SYNTH-AT-1');
    expect(http.calls).toEqual(['SYNTH-RT-0', 'SYNTH-RT-0']);
  });
});

describe('file lock', () => {
  test('serialises critical sections and reclaims a stale lock', async () => {
    const lock = join(dir, 'x.lock');
    let inside = 0;
    let maxInside = 0;
    await Promise.all(
      Array.from({ length: 5 }, () =>
        withFileLock(
          lock,
          async () => {
            inside++;
            maxInside = Math.max(maxInside, inside);
            await new Promise((r) => setTimeout(r, 5));
            inside--;
          },
          { pollMs: 2 },
        ),
      ),
    );
    expect(maxInside).toBe(1);

    // A lock left behind by a crashed process is older than staleMs.
    const handle = await open(lock, 'wx');
    await handle.close();
    const release = await acquireFileLock(lock, { staleMs: 1, pollMs: 2, timeoutMs: 2_000 });
    await release();
  });

  test('gives up with FileLockError rather than proceeding unlocked', async () => {
    const lock = join(dir, 'held.lock');
    const release = await acquireFileLock(lock);
    try {
      await expect(
        acquireFileLock(lock, { timeoutMs: 40, pollMs: 5, staleMs: 60_000 }),
      ).rejects.toBeInstanceOf(FileLockError);
    } finally {
      await release();
    }
  });
});

describe('TokenRefresher', () => {
  test('parallel callers on a warmed, expired cache share one refresh', async () => {
    const store = fileStore();
    await store.save(record(tokens({ expires_at: now() + 5 })));
    const http = new FakeHttp();
    const refresher = new TokenRefresher({
      store,
      http: asHttp(http),
      recheckIntervalMs: 0,
    });
    // Warm the cache with a token that is inside the refresh buffer.
    // (expires in 5 s < 60 s buffer → counts as expired → one refresh.)
    http.delayMs = 20;
    const results = await Promise.all([
      refresher.getFresh(),
      refresher.getFresh(),
      refresher.getFresh(),
    ]);
    expect(http.calls).toHaveLength(1);
    expect(new Set(results.map((r) => r.tokens.access_token))).toEqual(new Set(['SYNTH-AT-1']));
  });

  test('a failure is not cached: the next caller retries and readiness records the error', async () => {
    const store = fileStore();
    await store.save(record(tokens({ expires_at: now() - 1 })));
    const http = new FakeHttp();
    http.failNext = 1;
    const refresher = new TokenRefresher({ store, http: asHttp(http), recheckIntervalMs: 0 });
    await expect(refresher.getFresh()).rejects.toThrow();
    expect(refresher.recentError?.message).toMatch(/500/);
    expect(refresher.current).toBeUndefined();
    const ok = await refresher.getFresh();
    expect(ok.tokens.access_token).toBe('SYNTH-AT-1');
    expect(refresher.recentError).toBeUndefined();
  });

  test('registry hands every session the same refresher for the same file', async () => {
    const http = new FakeHttp();
    const a = getTokenRefresher({ store: fileStore(), http: asHttp(http) });
    const b = getTokenRefresher({ store: fileStore(), http: asHttp(http) });
    expect(a).toBe(b);
    const other = getTokenRefresher({
      store: new EncryptedFileTokenStore({ filePath: join(dir, 'other.json') }),
      http: asHttp(http),
    });
    expect(other).not.toBe(a);
  });

  test('an out-of-band logout is noticed on the next re-read', async () => {
    const store = fileStore();
    await store.save(record(tokens()));
    const http = new FakeHttp();
    const refresher = new TokenRefresher({ store, http: asHttp(http), recheckIntervalMs: 0 });
    expect((await refresher.getFresh()).username).toBe('synthetic-user');
    await store.clear();
    await expect(refresher.getFresh()).rejects.toThrow(/aula login/);
    expect(refresher.current).toBeUndefined();
  });
});
