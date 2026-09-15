/**
 * Minimal cross-process mutex built on `open(path, 'wx')`.
 *
 * The token store is shared by every process that can refresh credentials:
 * the MCP server, the CLI, and — during an overlapping deploy — a second
 * server. A refresh token is single-use on providers that rotate, so two
 * processes refreshing from the same stored token is a real failure mode,
 * not a theoretical one. `O_EXCL` creation is atomic on every filesystem we
 * care about (local disks, Docker volumes, tmpfs); NFS is out of scope.
 *
 * A lock left behind by a crashed process is reclaimed once it is older than
 * `staleMs`. Waiting callers poll with a small jittered sleep and give up
 * after `timeoutMs` with a TokenStoreError rather than proceeding unlocked —
 * the caller can retry, and a stuck lock surfaces as an error instead of a
 * silent double refresh.
 */

import { mkdir, open, stat, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { AulaAuthError } from './errors.ts';
import type { Logger } from './logger.ts';
import { silentLogger } from './logger.ts';

export class FileLockError extends AulaAuthError {
  override readonly name: string = 'FileLockError';
}

export interface FileLockOptions {
  /** Give up waiting after this long. Default 20 s. */
  timeoutMs?: number;
  /** Treat an existing lock older than this as abandoned. Default 60 s. */
  staleMs?: number;
  /** Base poll interval while waiting. Default 50 ms (jittered). */
  pollMs?: number;
  logger?: Logger;
}

export async function withFileLock<T>(
  lockPath: string,
  fn: () => Promise<T>,
  options: FileLockOptions = {},
): Promise<T> {
  const release = await acquireFileLock(lockPath, options);
  try {
    return await fn();
  } finally {
    await release();
  }
}

export async function acquireFileLock(
  lockPath: string,
  options: FileLockOptions = {},
): Promise<() => Promise<void>> {
  const timeoutMs = options.timeoutMs ?? 20_000;
  const staleMs = options.staleMs ?? 60_000;
  const pollMs = options.pollMs ?? 50;
  const logger = options.logger ?? silentLogger;
  const started = Date.now();
  await mkdir(dirname(lockPath), { recursive: true, mode: 0o700 });

  for (;;) {
    try {
      const handle = await open(lockPath, 'wx', 0o600);
      try {
        await handle.writeFile(`${process.pid} ${new Date().toISOString()}\n`, 'utf8');
      } finally {
        await handle.close();
      }
      return async () => {
        await unlink(lockPath).catch(() => {});
      };
    } catch (e) {
      if ((e as { code?: string }).code !== 'EEXIST') throw e;
    }

    // Lock exists. Reclaim if stale, otherwise wait.
    try {
      const s = await stat(lockPath);
      if (Date.now() - s.mtimeMs > staleMs) {
        logger.warn('file-lock.reclaiming_stale', { lockPath, ageMs: Date.now() - s.mtimeMs });
        await unlink(lockPath).catch(() => {});
        continue;
      }
    } catch (e) {
      // Vanished between open() and stat() — the holder released. Retry now.
      if ((e as { code?: string }).code === 'ENOENT') continue;
      throw e;
    }

    if (Date.now() - started > timeoutMs) {
      throw new FileLockError(
        `Timed out after ${timeoutMs} ms waiting for lock ${lockPath}. ` +
          'Another process is refreshing the same tokens; retry shortly.',
      );
    }
    await sleep(pollMs + Math.floor(Math.random() * pollMs));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
