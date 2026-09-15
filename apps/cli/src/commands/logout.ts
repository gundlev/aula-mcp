/**
 * `aula logout` — removes every piece of authentication state this CLI
 * wrote: the encrypted token store and, if present, the opt-in cookie jar.
 * The encryption key file is left in place so the next login re-uses it.
 *
 * This process cannot revoke the Aula refresh token upstream (Aula has no
 * documented revocation endpoint we have verified). Anyone who already
 * copied the tokens can keep refreshing until Aula expires the chain.
 * After logout, a running MCP server notices the missing file via its
 * watcher / refresher and stops serving with those credentials.
 */

import { unlink } from 'node:fs/promises';
import { resetTokenRefreshers } from '@aula-mcp/aula-auth';
import { ok } from '../io.ts';
import { cookiesFile, defaultStore } from '../store.ts';

export async function runLogout(): Promise<void> {
  const store = defaultStore();
  await store.clear();
  try {
    await unlink(cookiesFile());
  } catch (e) {
    if ((e as { code?: string }).code !== 'ENOENT') throw e;
  }
  resetTokenRefreshers();
  ok('Logged out. Tokens and any persisted cookies cleared.');
}
