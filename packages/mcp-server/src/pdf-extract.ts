/**
 * Bounded PDF text extraction (audit findings 3 and 6).
 *
 * The parent never parses a PDF itself. It checks the file (size, magic
 * bytes) and hands the path to `pdf-worker.ts` in a child Bun process with
 * a page cap, an output cap and a wall-clock deadline; on timeout the child
 * is killed. The worker's stdout is read up to a fixed size so a parser
 * that emits garbage cannot balloon the parent either.
 *
 * Memory is bounded at process level: the worker is a separate process,
 * so the container's cgroup memory limit (see deploy/coolify) — or an OOM
 * kill of the worker — never takes the MCP server down.
 */

import { open } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export interface PdfLimits {
  /** Refuse files larger than this without opening them. Default 25 MiB. */
  maxBytes: number;
  /** Pages to parse (from the start). Default 60. */
  maxPages: number;
  /** Characters of text to return. Default 400 000. */
  maxChars: number;
  /** Worker deadline. Default 30 s. */
  timeoutMs: number;
}

export const DEFAULT_PDF_LIMITS: PdfLimits = {
  maxBytes: 25 * 1024 * 1024,
  maxPages: 60,
  maxChars: 400_000,
  timeoutMs: 30_000,
};

export function pdfLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): PdfLimits {
  const int = (raw: string | undefined, fallback: number): number => {
    const n = Number(raw);
    return Number.isInteger(n) && n > 0 ? n : fallback;
  };
  return {
    maxBytes: int(env.AULA_MCP_PDF_MAX_BYTES, DEFAULT_PDF_LIMITS.maxBytes),
    maxPages: int(env.AULA_MCP_PDF_MAX_PAGES, DEFAULT_PDF_LIMITS.maxPages),
    maxChars: int(env.AULA_MCP_PDF_MAX_CHARS, DEFAULT_PDF_LIMITS.maxChars),
    timeoutMs: int(env.AULA_MCP_PDF_TIMEOUT_MS, DEFAULT_PDF_LIMITS.timeoutMs),
  };
}

export type PdfExtractResult =
  | { ok: true; text: string; pages: number; pagesParsed: number; truncated: boolean }
  | {
      ok: false;
      error: 'pdf_too_large' | 'not_a_pdf' | 'pdf_timeout' | 'pdf_parse_failed';
      message?: string;
      bytes?: number;
      maxBytes?: number;
    };

/** Worker output is bounded independently of the text cap. */
const MAX_WORKER_STDOUT = 4 * 1024 * 1024;

export const DEFAULT_WORKER_PATH = fileURLToPath(new URL('./pdf-worker.ts', import.meta.url));

export interface PdfExtractDeps {
  /** Script spawned as the worker. Tests point this at a stub. */
  workerPath?: string;
}

/**
 * Extract text from a PDF that has already been resolved through the
 * attachment store (`realPath` is a verified regular file inside the root
 * and `size` is its stat size).
 */
export async function extractPdfText(
  realPath: string,
  size: number,
  limits: PdfLimits = DEFAULT_PDF_LIMITS,
  deps: PdfExtractDeps = {},
): Promise<PdfExtractResult> {
  if (size > limits.maxBytes) {
    return { ok: false, error: 'pdf_too_large', bytes: size, maxBytes: limits.maxBytes };
  }
  if (!(await hasPdfMagic(realPath))) return { ok: false, error: 'not_a_pdf' };

  const workerPath = deps.workerPath ?? DEFAULT_WORKER_PATH;
  const proc = Bun.spawn(
    [
      process.execPath,
      workerPath,
      realPath,
      JSON.stringify({ maxPages: limits.maxPages, maxChars: limits.maxChars }),
    ],
    {
      stdin: 'ignore',
      stdout: 'pipe',
      stderr: 'pipe',
      // The worker needs no credentials and no configuration from us.
      env: {
        PATH: process.env.PATH ?? '',
        HOME: process.env.HOME ?? '/tmp',
        NODE_ENV: 'production',
      },
    },
  );

  let timedOut = false;
  let overflowed = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill('SIGKILL');
  }, limits.timeoutMs);

  try {
    // stderr is drained concurrently so a chatty worker cannot wedge on a
    // full pipe; its content is discarded.
    const stderrDrain = readBoundedStream(proc.stderr, 64 * 1024, () => {}).catch(() => '');
    const [stdout, exitCode] = await Promise.all([
      readBoundedStream(proc.stdout, MAX_WORKER_STDOUT, () => {
        // A worker that will not stop talking is treated like one that will
        // not stop running.
        overflowed = true;
        proc.kill('SIGKILL');
      }),
      proc.exited,
    ]);
    await stderrDrain;
    if (timedOut) {
      return { ok: false, error: 'pdf_timeout', message: `exceeded ${limits.timeoutMs} ms` };
    }
    if (overflowed) {
      return { ok: false, error: 'pdf_parse_failed', message: 'worker output exceeded the cap' };
    }
    let parsed: {
      ok: boolean;
      text?: string;
      pages?: number;
      pagesParsed?: number;
      truncated?: boolean;
      message?: string;
    };
    try {
      parsed = JSON.parse(stdout) as typeof parsed;
    } catch {
      return {
        ok: false,
        error: 'pdf_parse_failed',
        message: `worker exited ${exitCode} without a result`,
      };
    }
    if (!parsed.ok) {
      return { ok: false, error: 'pdf_parse_failed', message: parsed.message ?? 'unknown error' };
    }
    return {
      ok: true,
      text: parsed.text ?? '',
      pages: parsed.pages ?? 0,
      pagesParsed: parsed.pagesParsed ?? 0,
      truncated: parsed.truncated === true,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function hasPdfMagic(path: string): Promise<boolean> {
  const handle = await open(path, 'r');
  try {
    const buf = Buffer.alloc(1024);
    const { bytesRead } = await handle.read(buf, 0, 1024, 0);
    return buf.subarray(0, bytesRead).includes('%PDF-');
  } finally {
    await handle.close();
  }
}

/**
 * Collect a stream up to `max` bytes. Past the cap the rest is read and
 * discarded (so the child never blocks on a full pipe) and `onOverflow`
 * fires once.
 */
async function readBoundedStream(
  stream: ReadableStream<Uint8Array> | number | undefined | null,
  max: number,
  onOverflow: () => void,
): Promise<string> {
  if (!stream || typeof stream === 'number') return '';
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let overflowed = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (overflowed) continue;
    if (total + value.length > max) {
      chunks.push(value.subarray(0, Math.max(0, max - total)));
      total = max;
      overflowed = true;
      onOverflow();
      continue;
    }
    chunks.push(value);
    total += value.length;
  }
  return Buffer.concat(chunks).toString('utf8');
}
