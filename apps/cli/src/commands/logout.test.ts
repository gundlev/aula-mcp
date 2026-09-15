/**
 * Logout must remove every piece of authentication state the CLI wrote
 * (audit finding 8): tokens.json *and* cookies.json. The encryption key
 * stays so the next login can reuse it.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptedFileTokenStore, type StoredTokenRecord } from '@aula-mcp/aula-auth';

let runLogout: typeof import('./logout.ts')['runLogout'];

beforeAll(async () => {
  process.env.AULA_MCP_NO_KEYCHAIN = '1';
  const mod = await import('./logout.ts');
  runLogout = mod.runLogout;
});

const RECORD: StoredTokenRecord = {
  version: 1,
  username: 'synthetic-user',
  saved_at: 1_700_000_000,
  tokens: {
    access_token: 'SYNTH-AT',
    refresh_token: 'SYNTH-RT',
    token_type: 'Bearer',
    expires_in: 3600,
    expires_at: 1_700_003_600,
    obtained_at: 1_700_000_000,
  },
};

let dir: string;

beforeEach(async () => {
  const { mkdtemp } = await import('node:fs/promises');
  dir = await mkdtemp(join(tmpdir(), 'aula-logout-'));
  process.env.AULA_MCP_DIR = dir;
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('aula logout', () => {
  test('clears the token store and deletes cookies.json, leaving .key', async () => {
    const store = new EncryptedFileTokenStore({
      filePath: join(dir, 'tokens.json'),
      keyFilePath: join(dir, '.key'),
      ignoreEnv: true,
    });
    await store.save(RECORD);
    await writeFile(join(dir, 'cookies.json'), '{"cookies":[{"name":"SYNTH-SESSION","value":"keep-me"}]}', {
      mode: 0o600,
    });

    await runLogout();

    expect(await store.load()).toBeNull();
    await expect(readFile(join(dir, 'cookies.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    expect((await readFile(join(dir, '.key'), 'utf8')).length).toBeGreaterThan(0);
  });

  test('succeeds when there is nothing to clear', async () => {
    await mkdir(dir, { recursive: true });
    await runLogout();
    expect(true).toBe(true);
  });
});
