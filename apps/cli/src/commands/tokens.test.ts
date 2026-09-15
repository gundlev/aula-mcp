/**
 * Round-trip test for `aula tokens export` / `import`. We run the export
 * against a file-backed source store, then import it elsewhere and check
 * the round-tripped record matches byte-for-byte.
 *
 * The CLI helpers use `defaultStore()` under the hood, which selects
 * Keychain on macOS. To keep the test hermetic + cross-platform we set
 * `AULA_MCP_NO_KEYCHAIN=1` before importing the helpers — that forces
 * the file backend on every platform.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptedFileTokenStore, type StoredTokenRecord } from '@aula-mcp/aula-auth';

let runTokensExport: typeof import('./tokens.ts')['runTokensExport'];
let runTokensImport: typeof import('./tokens.ts')['runTokensImport'];

beforeAll(async () => {
  process.env.AULA_MCP_NO_KEYCHAIN = '1';
  const mod = await import('./tokens.ts');
  runTokensExport = mod.runTokensExport;
  runTokensImport = mod.runTokensImport;
});

const FAKE_RECORD: StoredTokenRecord = {
  version: 1,
  username: 'demo',
  identityName: 'Demo User',
  saved_at: 1_700_000_000,
  tokens: {
    access_token: 'AT-1',
    refresh_token: 'RT-1',
    token_type: 'Bearer',
    expires_in: 3600,
    expires_at: 1_700_003_600,
    obtained_at: 1_700_000_000,
  },
};

let workDir: string;

beforeEach(async () => {
  workDir = await mkdtemp(join(tmpdir(), 'aula-tokens-test-'));
  // Point the local store at a per-test dir so we don't touch ~/.config.
  process.env.AULA_MCP_DIR = join(workDir, 'local');
});

afterEach(async () => {
  delete process.env.AULA_MCP_KEY;
  await rm(workDir, { recursive: true, force: true });
});

describe('tokens export → import round-trip', () => {
  test('produces a self-contained bundle that imports cleanly', async () => {
    // 1. Seed the local store with a record.
    const localStore = new EncryptedFileTokenStore({
      filePath: join(workDir, 'local', 'tokens.json'),
      keyFilePath: join(workDir, 'local', '.key'),
    });
    await localStore.save(FAKE_RECORD);

    // 2. Export to a bundle dir.
    const bundleDir = join(workDir, 'bundle');
    await runTokensExport({ outDir: bundleDir });

    // Both bundle files exist + key is 32 bytes (256-bit AES key, hex-encoded).
    const bundleKey = await readFile(join(bundleDir, '.key'), 'utf8');
    expect(bundleKey.length).toBe(64); // 32 bytes hex-encoded
    const bundleTokens = await readFile(join(bundleDir, 'tokens.json'), 'utf8');
    expect(bundleTokens.length).toBeGreaterThan(0);

    // 3. Move to a "remote" dir (swap AULA_MCP_DIR) and import.
    process.env.AULA_MCP_DIR = join(workDir, 'remote');
    await runTokensImport({ inDir: bundleDir });

    // 4. The remote store now has the same record.
    const remoteStore = new EncryptedFileTokenStore({
      filePath: join(workDir, 'remote', 'tokens.json'),
      keyFilePath: join(workDir, 'remote', '.key'),
    });
    const remoteRecord = await remoteStore.load();
    expect(remoteRecord).toEqual(FAKE_RECORD);
  });

  test('export uses a fresh key, not the local store key', async () => {
    const localStore = new EncryptedFileTokenStore({
      filePath: join(workDir, 'local', 'tokens.json'),
      keyFilePath: join(workDir, 'local', '.key'),
    });
    await localStore.save(FAKE_RECORD);
    const localKey = await readFile(join(workDir, 'local', '.key'), 'utf8');

    await runTokensExport({ outDir: join(workDir, 'bundle') });
    const bundleKey = await readFile(join(workDir, 'bundle', '.key'), 'utf8');

    // Different keys — important so deleting the bundle never affects the
    // original install, and so a leaked bundle can't be used to decrypt
    // anything else encrypted with the local key.
    expect(bundleKey).not.toBe(localKey);
  });

  test('export writes .key even when AULA_MCP_KEY is set, and does not use that key', async () => {
    process.env.AULA_MCP_KEY = 'aa'.repeat(32);
    const localStore = new EncryptedFileTokenStore({
      filePath: join(workDir, 'local', 'tokens.json'),
      keyFilePath: join(workDir, 'local', '.key'),
    });
    await localStore.save(FAKE_RECORD);

    const bundleDir = join(workDir, 'bundle');
    await runTokensExport({ outDir: bundleDir });
    const bundleKey = (await readFile(join(bundleDir, '.key'), 'utf8')).trim();
    expect(bundleKey).toHaveLength(64);
    expect(bundleKey).not.toBe(process.env.AULA_MCP_KEY);

    // The bundle decrypts with its own key, not the env key.
    const viaBundleKey = new EncryptedFileTokenStore({
      filePath: join(bundleDir, 'tokens.json'),
      keyFilePath: join(bundleDir, '.key'),
      ignoreEnv: true,
    });
    expect(await viaBundleKey.load()).toEqual(FAKE_RECORD);
    const viaEnv = new EncryptedFileTokenStore({
      filePath: join(bundleDir, 'tokens.json'),
      keyFilePath: join(bundleDir, 'missing.key'),
    });
    await expect(viaEnv.load()).rejects.toThrow();
    delete process.env.AULA_MCP_KEY;
  });

  test('import decrypts with the bundle key and re-encrypts with the destination key', async () => {
    process.env.AULA_MCP_KEY = 'bb'.repeat(32);
    const sourceDir = join(workDir, 'src-store');
    const source = new EncryptedFileTokenStore({
      filePath: join(sourceDir, 'tokens.json'),
      keyFilePath: join(sourceDir, '.key'),
    });
    await source.save(FAKE_RECORD);
    process.env.AULA_MCP_DIR = sourceDir;
    const bundleDir = join(workDir, 'bundle');
    await runTokensExport({ outDir: bundleDir });

    process.env.AULA_MCP_KEY = 'cc'.repeat(32);
    process.env.AULA_MCP_DIR = join(workDir, 'dest');
    await runTokensImport({ inDir: bundleDir });

    const dest = new EncryptedFileTokenStore({
      filePath: join(workDir, 'dest', 'tokens.json'),
      keyFilePath: join(workDir, 'dest', '.key'),
    });
    expect(await dest.load()).toEqual(FAKE_RECORD);
    delete process.env.AULA_MCP_KEY;
  });

  test('import fails closed when the bundle key is missing or wrong', async () => {
    const localStore = new EncryptedFileTokenStore({
      filePath: join(workDir, 'local', 'tokens.json'),
      keyFilePath: join(workDir, 'local', '.key'),
      ignoreEnv: true,
    });
    await localStore.save(FAKE_RECORD);
    const bundleDir = join(workDir, 'bundle');
    await runTokensExport({ outDir: bundleDir });

    const missing = join(workDir, 'missing-key');
    await mkdir(missing, { recursive: true });
    await Bun.write(join(missing, 'tokens.json'), await readFile(join(bundleDir, 'tokens.json')));
    const prev = process.exit;
    const exits: number[] = [];
    process.exit = ((code?: number) => {
      exits.push(code ?? 0);
      throw new Error(`exit ${code}`);
    }) as typeof process.exit;
    try {
      await expect(runTokensImport({ inDir: missing })).rejects.toThrow(/exit/);
      expect(exits).toEqual([1]);

      await Bun.write(join(bundleDir, '.key'), 'dd'.repeat(32));
      exits.length = 0;
      process.env.AULA_MCP_DIR = join(workDir, 'dest2');
      await expect(runTokensImport({ inDir: bundleDir })).rejects.toThrow(/exit/);
      expect(exits).toEqual([1]);
    } finally {
      process.exit = prev;
    }
  });
});
