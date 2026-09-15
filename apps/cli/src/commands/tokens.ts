/**
 * `aula tokens export <dir>` and `aula tokens import <dir>` — move tokens
 * between machines without hunting for two files manually.
 *
 * Both commands round-trip through the file-backed store
 * (`EncryptedFileTokenStore`), regardless of which backend is configured
 * locally. Export always produces a fresh AES-GCM key so the bundle is
 * self-contained, deletable, and doesn't expose the original `.key` from
 * the local file backend (if you happened to have one).
 *
 * Why two files (`tokens.json` + `.key`) instead of a single bundle? The
 * file backend is what every server-side install uses, so the export
 * format _is_ the install format. `scp <dir>/* server:/var/lib/aula-mcp/`
 * and you're done.
 */

import { mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import {
  decodeKeyMaterial,
  EncryptedFileTokenStore,
  generateKeyMaterial,
  readKeyFile,
  writeKeyFile,
} from '@aula-mcp/aula-auth';
import { fail, fmt, ok, warn } from '../io.ts';
import { defaultStore } from '../store.ts';

export interface TokensExportArgs {
  /** Output directory. Required. */
  outDir: string;
}

export interface TokensImportArgs {
  /** Input directory containing tokens.json + .key. Required. */
  inDir: string;
}

export async function runTokensExport(args: TokensExportArgs): Promise<void> {
  const localStore = defaultStore();
  const record = await localStore.load();
  if (!record) {
    fail('No tokens to export. Run `aula login` first.');
    process.exit(1);
  }

  const outDir = resolve(args.outDir);
  const tokensFile = join(outDir, 'tokens.json');
  const keyFile = join(outDir, '.key');
  await mkdir(outDir, { recursive: true });

  // Independent key material for the bundle. Passing it explicitly (and
  // ignoring AULA_MCP_KEY) is what keeps a workstation env key from
  // encrypting the export — the audit reproduced a "success" that never
  // wrote `.key` because resolveKey() short-circuited on the env var.
  const material = generateKeyMaterial();
  await writeKeyFile(keyFile, material);
  const exportStore = new EncryptedFileTokenStore({
    filePath: tokensFile,
    keyFilePath: keyFile,
    key: decodeKeyMaterial(material),
    ignoreEnv: true,
  });
  await exportStore.save(record);

  ok(`Exported tokens to ${fmt.dim(outDir)}`);
  warn('Both files contain live credentials — treat them like a password.');
  warn(`After the transfer, delete ${fmt.dim(outDir)} on this machine.`);
  process.stdout.write(
    `\n${fmt.bold('Move to a server:')}\n  scp ${outDir}/tokens.json ${outDir}/.key user@server:/var/lib/aula-mcp/\n` +
      `\n${fmt.bold('Or import on another machine:')}\n  aula tokens import ${outDir}\n` +
      `\nThe server decrypts the bundle with ${fmt.dim('.key')} and re-encrypts with its own key\n` +
      `(AULA_MCP_KEY or its own .key). Do not copy the workstation AULA_MCP_KEY.\n`,
  );
}

export async function runTokensImport(args: TokensImportArgs): Promise<void> {
  const inDir = resolve(args.inDir);
  // Decrypt with the bundle's own `.key`. Never inherit AULA_MCP_KEY — that
  // is the destination store's key and decrypts a foreign envelope as garbage.
  let record: Awaited<ReturnType<EncryptedFileTokenStore['load']>>;
  try {
    const bundleKey = await readKeyFile(join(inDir, '.key'));
    const sourceStore = new EncryptedFileTokenStore({
      filePath: join(inDir, 'tokens.json'),
      keyFilePath: join(inDir, '.key'),
      key: bundleKey,
      ignoreEnv: true,
    });
    record = await sourceStore.load();
  } catch (e) {
    fail(`Failed to read token bundle from ${inDir}: ${(e as Error).message}`);
    process.exit(1);
  }
  if (!record) {
    fail(
      `No tokens found in ${inDir}. Expected ${fmt.dim('tokens.json')} + ${fmt.dim('.key')} from a previous \`aula tokens export\`.`,
    );
    process.exit(1);
  }

  const targetStore = defaultStore();
  await mkdir(dirname(targetStore.path === inDir ? '/dev/null' : targetStore.path), {
    recursive: true,
  }).catch(() => {
    // Keychain backend has no real directory; ignore.
  });
  await targetStore.save(record);

  ok(`Imported tokens for ${fmt.bold(record.username)} into ${fmt.dim(targetStore.path)}`);
  if (record.identityName) process.stdout.write(`• Identity: ${record.identityName}\n`);
}
