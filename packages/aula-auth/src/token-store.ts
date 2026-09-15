/**
 * Token persistence. The MCP server / CLI both load tokens from here so we
 * don't make the user re-do MitID for every process.
 *
 * Design:
 *   - `TokenStore` is the pluggable interface (load / save / clear).
 *   - `MemoryTokenStore` for tests + ephemeral runs.
 *   - `EncryptedFileTokenStore` writes a JSON envelope (version + IV +
 *     ciphertext + tag) at `~/.config/aula-mcp/tokens.json` (override path
 *     via constructor). The encryption key comes from one of:
 *       1. an explicit Buffer passed to the constructor (keychain integration
 *          can read its key and pass it in),
 *       2. process.env.AULA_MCP_KEY (hex-encoded 32-byte key),
 *       3. a key file at `~/.config/aula-mcp/.key` (created with chmod 600
 *          on first use). We warn that 1 or 2 are stronger.
 *
 * The persisted record includes the active identity (so multi-child guardians
 * don't have to re-pick on every refresh) and a `version` to allow future
 * format changes without losing data.
 */

import { Buffer } from 'node:buffer';
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  type AulaOAuthConfig,
  type AulaTokens,
  DEFAULT_OAUTH_CONFIG,
  isTokenExpired,
  refreshAccessToken,
} from './aula-oauth.ts';
import { aesGcmDecrypt, aesGcmEncrypt, randomBytes, sha256 } from './crypto.ts';
import { hexToBytes } from './encoding.ts';
import { AulaAuthError } from './errors.ts';
import { withFileLock } from './file-lock.ts';
import type { AulaHttpClient } from './http.ts';
import type { Logger } from './logger.ts';
import { silentLogger } from './logger.ts';

export class TokenStoreError extends AulaAuthError {
  override readonly name: string = 'TokenStoreError';
}

/** Persisted record. The shape is bumped via `version` if we change anything. */
export interface StoredTokenRecord {
  version: 1;
  username: string;
  tokens: AulaTokens;
  /** The MitID identity index the user picked (1-based). Optional: unset when
   *  the user has only one identity / hasn't yet selected. */
  identityIndex?: number;
  /** Display name for the chosen identity (helpful for `aula status`). */
  identityName?: string;
  /** When the record was last written. Unix epoch seconds. */
  saved_at: number;
  /** Free-form metadata bag — debug only. */
  meta?: Record<string, unknown>;
}

export interface TokenStore {
  load(): Promise<StoredTokenRecord | null>;
  save(record: StoredTokenRecord): Promise<void>;
  clear(): Promise<void>;
}

// --------------------------------------------------------------------------
// MemoryTokenStore
// --------------------------------------------------------------------------

export class MemoryTokenStore implements TokenStore {
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

// --------------------------------------------------------------------------
// EncryptedFileTokenStore
// --------------------------------------------------------------------------

export interface EncryptedFileTokenStoreOptions {
  /** Defaults to `~/.config/aula-mcp/tokens.json`. */
  filePath?: string;
  /** Defaults to `~/.config/aula-mcp/.key`. */
  keyFilePath?: string;
  /** Force-supply the 32-byte AES-GCM key (e.g. from a keychain). Wins over
   *  env / file. */
  key?: Buffer;
  /** Override env var lookup. */
  envVarName?: string;
  /** Skip `process.env[envVarName]` entirely. Export/import bundles use this
   *  so a workstation's `AULA_MCP_KEY` cannot encrypt or decrypt the bundle. */
  ignoreEnv?: boolean;
  logger?: Logger;
}

interface EncryptedEnvelope {
  version: 1;
  /** AES-256-GCM. */
  alg: 'aes-256-gcm';
  /** 16-byte IV, base64. */
  iv: string;
  /** Ciphertext, base64. */
  ct: string;
  /** Auth tag, base64. */
  tag: string;
}

const DEFAULT_DIR = join(homedir(), '.config', 'aula-mcp');
const DEFAULT_FILE = join(DEFAULT_DIR, 'tokens.json');
const DEFAULT_KEY_FILE = join(DEFAULT_DIR, '.key');
const DEFAULT_ENV = 'AULA_MCP_KEY';

export class EncryptedFileTokenStore implements TokenStore {
  /** Resolved on-disk path. Exposed (read-only) so long-lived consumers can
   *  watch it for external writes (e.g. `aula login` from another process
   *  rotating tokens beneath a running MCP server). */
  readonly filePath: string;
  private readonly keyFilePath: string;
  private readonly envVar: string;
  private readonly ignoreEnv: boolean;
  private readonly explicitKey?: Buffer;
  private readonly logger: Logger;
  private cachedKey?: Buffer;

  constructor(opts: EncryptedFileTokenStoreOptions = {}) {
    this.filePath = opts.filePath ?? DEFAULT_FILE;
    this.keyFilePath = opts.keyFilePath ?? DEFAULT_KEY_FILE;
    this.envVar = opts.envVarName ?? DEFAULT_ENV;
    this.ignoreEnv = opts.ignoreEnv === true;
    if (opts.key) this.explicitKey = opts.key;
    this.logger = opts.logger ?? silentLogger;
  }

  async load(): Promise<StoredTokenRecord | null> {
    let raw: string;
    try {
      raw = await readFile(this.filePath, 'utf8');
    } catch (e) {
      if (isEnoent(e)) return null;
      throw new TokenStoreError(`Failed to read token file ${this.filePath}`, { cause: e });
    }
    let envelope: EncryptedEnvelope;
    try {
      envelope = JSON.parse(raw) as EncryptedEnvelope;
    } catch (e) {
      throw new TokenStoreError('Token file is not valid JSON', { cause: e });
    }
    if (envelope.version !== 1 || envelope.alg !== 'aes-256-gcm') {
      throw new TokenStoreError(
        `Unsupported token file envelope (version=${envelope.version}, alg=${envelope.alg})`,
      );
    }
    const key = await this.resolveKey();
    let plaintext: Buffer;
    try {
      plaintext = aesGcmDecrypt(
        key,
        Buffer.from(envelope.iv, 'base64'),
        Buffer.from(envelope.ct, 'base64'),
        Buffer.from(envelope.tag, 'base64'),
      );
    } catch (e) {
      throw new TokenStoreError(
        'Failed to decrypt token file. Wrong AULA_MCP_KEY, or the key file is missing/corrupted.',
        { cause: e },
      );
    }
    let record: StoredTokenRecord;
    try {
      record = JSON.parse(plaintext.toString('utf8')) as StoredTokenRecord;
    } catch (e) {
      throw new TokenStoreError('Decrypted token blob is not valid JSON', { cause: e });
    }
    if (record.version !== 1) {
      throw new TokenStoreError(`Unsupported token record version ${record.version}`);
    }
    return record;
  }

  async save(record: StoredTokenRecord): Promise<void> {
    const key = await this.resolveKey();
    const iv = randomBytes(16);
    const { ciphertext, tag } = aesGcmEncrypt(key, iv, Buffer.from(JSON.stringify(record), 'utf8'));
    const envelope: EncryptedEnvelope = {
      version: 1,
      alg: 'aes-256-gcm',
      iv: iv.toString('base64'),
      ct: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
    };
    await writeFileAtomic(this.filePath, JSON.stringify(envelope, null, 2));
  }

  async clear(): Promise<void> {
    // Delete the file outright. `load()` returns null for missing files, so a
    // post-clear `load()` rightly reports "no tokens" instead of throwing on
    // an empty-string parse. The .key file is intentionally left in place so
    // the next login can reuse the same encryption key.
    try {
      await unlink(this.filePath);
    } catch (e) {
      if (!isEnoent(e)) throw e;
    }
  }

  /** Where the encrypted JSON lives. Useful for `aula status`. */
  get path(): string {
    return this.filePath;
  }

  /** Lock file that serialises refreshes across processes sharing this file. */
  get lockPath(): string {
    return `${this.filePath}.lock`;
  }

  // ---- key resolution ------------------------------------------------------

  private async resolveKey(): Promise<Buffer> {
    if (this.cachedKey) return this.cachedKey;
    if (this.explicitKey) {
      assertKeyLength(this.explicitKey);
      this.cachedKey = this.explicitKey;
      return this.cachedKey;
    }
    const envValue = this.ignoreEnv ? undefined : process.env[this.envVar];
    if (envValue) {
      const buf = decodeKeyMaterial(envValue);
      this.cachedKey = buf;
      this.logger.debug('token-store.key.from_env', { envVar: this.envVar });
      return this.cachedKey;
    }
    // Fall back to a key file.
    let fileContents: string;
    try {
      fileContents = (await readFile(this.keyFilePath, 'utf8')).trim();
    } catch (e) {
      if (isEnoent(e)) {
        const fresh = randomBytes(32);
        await writeKeyFile(this.keyFilePath, fresh.toString('hex'));
        this.logger.warn('token-store.key.generated', {
          path: this.keyFilePath,
          note: `For better security, set ${this.envVar}=<hex> or pass a keychain-managed key.`,
        });
        this.cachedKey = fresh;
        return this.cachedKey;
      }
      throw new TokenStoreError(`Failed to read key file ${this.keyFilePath}`, { cause: e });
    }
    const buf = decodeKeyMaterial(fileContents);
    this.cachedKey = buf;
    return this.cachedKey;
  }
}

/**
 * Turn key material (env var or `.key` file contents) into a 32-byte key.
 * 64 hex characters are taken verbatim; anything else is treated as a
 * passphrase and hashed. `isStrongKeyMaterial` tells the two apart so a
 * deployment can warn when a passphrase is used where a random key belongs.
 */
export function decodeKeyMaterial(material: string): Buffer {
  const trimmed = material.trim();
  // Accept hex (64 chars) or base64 (44 chars including padding).
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return hexToBytes(trimmed);
  }
  // Hash anything else with SHA-256 to derive a 32-byte key — works for
  // arbitrary passphrases and keeps the API forgiving.
  return sha256(trimmed);
}

/** True when `material` is a full 32-byte hex key rather than a passphrase. */
export function isStrongKeyMaterial(material: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(material.trim());
}

/** 32 cryptographically random bytes, hex-encoded — the production key format. */
export function generateKeyMaterial(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Read a `.key` file and decode it. Throws a TokenStoreError (not a raw
 * ENOENT) so callers such as `aula tokens import` can report a missing bundle
 * key in plain words instead of decrypting against an unrelated env key.
 */
export async function readKeyFile(path: string): Promise<Buffer> {
  let contents: string;
  try {
    contents = await readFile(path, 'utf8');
  } catch (e) {
    if (isEnoent(e)) throw new TokenStoreError(`Key file ${path} does not exist`, { cause: e });
    throw new TokenStoreError(`Failed to read key file ${path}`, { cause: e });
  }
  if (!contents.trim()) throw new TokenStoreError(`Key file ${path} is empty`);
  return decodeKeyMaterial(contents);
}

/** Write key material with owner-only permissions from the moment it exists. */
export async function writeKeyFile(path: string, material: string): Promise<void> {
  await writeFileAtomic(path, material);
}

/**
 * Write `contents` to `path` without ever exposing a partially written or
 * world-readable file: the data lands in a same-directory temp file created
 * with mode 0600, is fsync'd, and is then renamed over the target. Readers
 * see either the old file or the new one, never a torn write, and a crash
 * mid-save leaves the previous credentials intact.
 */
export async function writeFileAtomic(path: string, contents: string): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = join(
    dir,
    `.${basenameOf(path)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  const handle = await open(tmp, 'wx', 0o600);
  try {
    await handle.writeFile(contents, 'utf8');
    try {
      await handle.sync();
    } catch {
      // Some filesystems (tmpfs on certain kernels, network shares) reject
      // fsync; the rename below is still atomic on the same filesystem.
    }
  } finally {
    await handle.close();
  }
  try {
    // The rename target may pre-exist with looser permissions from an older
    // version; the temp file's 0600 travels with the inode, so the result is
    // owner-only regardless.
    await rename(tmp, path);
  } catch (e) {
    await unlink(tmp).catch(() => {});
    throw e;
  }
  try {
    await chmod(path, 0o600);
  } catch {
    // chmod may fail on some filesystems (NTFS share, etc.) — non-fatal; the
    // file was created 0600 already.
  }
}

function basenameOf(path: string): string {
  const idx = path.lastIndexOf('/');
  return idx === -1 ? path : path.slice(idx + 1);
}

function assertKeyLength(key: Buffer): void {
  if (key.length !== 32) {
    throw new TokenStoreError(`Token store key must be 32 bytes (got ${key.length})`);
  }
}

function isEnoent(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { code?: string }).code === 'ENOENT';
}

// --------------------------------------------------------------------------
// Refresh-on-load helper
// --------------------------------------------------------------------------

export interface WithFreshTokensArgs {
  store: TokenStore;
  http: AulaHttpClient;
  /** Override OAuth config (defaults to production constants). */
  oauth?: AulaOAuthConfig;
  /** Buffer in seconds before expiry that triggers a refresh. Default 60. */
  refreshBufferSeconds?: number;
  logger?: Logger;
  /**
   * Lock file used to serialise refreshes across processes that share the
   * same credentials (the MCP server and the CLI, or two server processes
   * during an overlapping deploy). Defaults to `<tokens.json>.lock` for
   * file-backed stores; `null` disables locking (memory / keychain stores).
   */
  lockPath?: string | null;
}

/**
 * Load the stored record and refresh the access token if it's near expiry.
 * Saves the new tokens back to the store. Returns the (possibly refreshed)
 * record. Throws if no record is present.
 *
 * Refreshes are serialised through a lock file when the store is file-backed
 * and re-read the store once the lock is held, so a second process that
 * queued behind a refresh adopts the fresh tokens instead of spending the
 * same refresh token again. Before persisting, the store is read one final
 * time: if someone else (a new `aula login`, another refresher) has already
 * written newer valid tokens, theirs win and ours are discarded — a stale
 * write must never clobber a rotated refresh token.
 */
export async function withFreshTokens(args: WithFreshTokensArgs): Promise<StoredTokenRecord> {
  const logger = args.logger ?? silentLogger;
  const oauth = args.oauth ?? DEFAULT_OAUTH_CONFIG;
  const buffer = args.refreshBufferSeconds ?? 60;
  const record = await args.store.load();
  if (!record) {
    throw new TokenStoreError('No tokens on disk. Run `aula login` first.');
  }
  if (!isTokenExpired(record.tokens, buffer)) {
    return record;
  }

  const lockPath = args.lockPath === undefined ? deriveLockPath(args.store) : args.lockPath;
  const refresh = async (): Promise<StoredTokenRecord> => {
    // Another process may have refreshed — or logged out — while we waited
    // for the lock. Re-read rather than trusting the record from before.
    const current = await args.store.load();
    if (!current) {
      throw new TokenStoreError('Tokens were removed while waiting to refresh. Run `aula login`.');
    }
    if (!isTokenExpired(current.tokens, buffer)) {
      logger.info('token-store.refresh.adopted_concurrent');
      return current;
    }
    logger.info('token-store.refresh.start');
    const refreshed = await refreshAccessToken(
      args.http,
      oauth,
      current.tokens.refresh_token,
      logger,
    );
    const latest = await args.store.load();
    if (!latest) {
      // Logged out mid-refresh. The user just revoked access; do not
      // resurrect the credentials on disk or hand them to this caller.
      logger.warn('token-store.refresh.store_cleared_during_refresh');
      throw new TokenStoreError('Tokens were removed during refresh. Run `aula login`.');
    }
    if (
      latest.tokens.access_token !== current.tokens.access_token &&
      !isTokenExpired(latest.tokens, buffer)
    ) {
      logger.info('token-store.refresh.stale_write_prevented');
      return latest;
    }
    const updated: StoredTokenRecord = {
      ...latest,
      tokens: refreshed,
      saved_at: Math.floor(Date.now() / 1000),
    };
    await args.store.save(updated);
    return updated;
  };

  if (!lockPath) return refresh();
  return withFileLock(lockPath, refresh, { logger });
}

/** `<tokens.json>.lock` for file-backed stores, `null` for everything else. */
export function deriveLockPath(store: TokenStore): string | null {
  const filePath = (store as { filePath?: unknown }).filePath;
  return typeof filePath === 'string' && filePath.length > 0 ? `${filePath}.lock` : null;
}
