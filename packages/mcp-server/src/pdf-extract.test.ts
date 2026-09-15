/**
 * Regression tests for bounded, isolated PDF text extraction (audit
 * findings 3 and 6). The audit read an arbitrary path with `readFile()` and
 * parsed the whole file in-process with no limits. Fixtures are generated
 * here — synthetic single-font PDFs — and the worker is a real child
 * process, so what is asserted is the actual isolation boundary.
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  DEFAULT_PDF_LIMITS,
  extractPdfText,
  type PdfLimits,
  pdfLimitsFromEnv,
} from './pdf-extract.ts';
import { makeSyntheticPdf } from './test-fixtures.ts';

const limits: PdfLimits = {
  maxBytes: 1024 * 1024,
  maxPages: 60,
  maxChars: 400_000,
  timeoutMs: 20_000,
};

let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aula-pdf-test-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function fixture(
  name: string,
  contents: Buffer | string,
): Promise<{ path: string; size: number }> {
  const path = join(dir, name);
  await writeFile(path, contents);
  return { path, size: (await stat(path)).size };
}

describe('extractPdfText', () => {
  test('extracts the text of a normal PDF', async () => {
    const f = await fixture('plan.pdf', makeSyntheticPdf('Synthetic Aula', 2));
    const r = await extractPdfText(f.path, f.size, limits);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.text).toContain('Synthetic Aula page 1');
    expect(r.text).toContain('Synthetic Aula page 2');
    expect(r.pages).toBe(2);
    expect(r.pagesParsed).toBe(2);
    expect(r.truncated).toBe(false);
  });

  test('parses only maxPages pages and flags truncation', async () => {
    const f = await fixture('long.pdf', makeSyntheticPdf('Long', 5));
    const r = await extractPdfText(f.path, f.size, { ...limits, maxPages: 2 });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.pages).toBe(5);
    expect(r.pagesParsed).toBe(2);
    expect(r.truncated).toBe(true);
    expect(r.text).toContain('Long page 2');
    expect(r.text).not.toContain('Long page 3');
  });

  test('caps the returned characters and flags truncation', async () => {
    const f = await fixture('chars.pdf', makeSyntheticPdf('Chars', 3));
    const r = await extractPdfText(f.path, f.size, { ...limits, maxChars: 12 });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.text.length).toBe(12);
    expect(r.truncated).toBe(true);
  });

  test('refuses an oversized file from its size alone, without opening it', async () => {
    // Unreadable file: if the size check did not come first, open() would throw.
    const f = await fixture('big.pdf', makeSyntheticPdf('Big'));
    await chmod(f.path, 0o000);
    const r = await extractPdfText(f.path, limits.maxBytes + 1, limits);
    expect(r).toEqual({
      ok: false,
      error: 'pdf_too_large',
      bytes: limits.maxBytes + 1,
      maxBytes: limits.maxBytes,
    });
    await chmod(f.path, 0o600);
  });

  test('refuses a file that is not a PDF without spawning the worker', async () => {
    const f = await fixture('notes.txt', 'hello, this is not a pdf');
    const r = await extractPdfText(f.path, f.size, limits, {
      workerPath: '/nonexistent/worker.ts',
    });
    expect(r).toEqual({ ok: false, error: 'not_a_pdf' });
  });

  test('reports a parse failure for a corrupt PDF instead of throwing', async () => {
    const f = await fixture('corrupt.pdf', '%PDF-1.4\n%%garbage garbage garbage');
    const r = await extractPdfText(f.path, f.size, limits);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('pdf_parse_failed');
  });

  test('kills a worker that exceeds the deadline', async () => {
    const worker = join(dir, 'hang-worker.ts');
    await writeFile(worker, 'await new Promise(() => {});\n');
    const f = await fixture('plan.pdf', makeSyntheticPdf('Hang'));
    const started = Date.now();
    const r = await extractPdfText(
      f.path,
      f.size,
      { ...limits, timeoutMs: 300 },
      { workerPath: worker },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe('pdf_timeout');
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  test('treats a worker that crashes or emits garbage as a parse failure', async () => {
    const crash = join(dir, 'crash-worker.ts');
    await writeFile(crash, 'process.stdout.write("not json"); process.exit(3);\n');
    const f = await fixture('plan.pdf', makeSyntheticPdf('Crash'));
    const r = await extractPdfText(f.path, f.size, limits, { workerPath: crash });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toBe('pdf_parse_failed');
      expect(r.message).toContain('exited 3');
    }
  });

  test('bounds the worker output and kills a worker that floods stdout', async () => {
    const flood = join(dir, 'flood-worker.ts');
    await writeFile(
      flood,
      'const chunk = Buffer.alloc(1024 * 1024, 0x41);\nfor (;;) process.stdout.write(chunk);\n',
    );
    const f = await fixture('plan.pdf', makeSyntheticPdf('Flood'));
    const r = await extractPdfText(
      f.path,
      f.size,
      { ...limits, timeoutMs: 10_000 },
      { workerPath: flood },
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(['pdf_parse_failed', 'pdf_timeout']).toContain(r.error);
  });

  test('the worker gets no environment beyond PATH/HOME', async () => {
    const spy = join(dir, 'env-worker.ts');
    await writeFile(
      spy,
      'process.stdout.write(JSON.stringify({ ok: true, text: Object.keys(process.env).sort().join(","), pages: 0, pagesParsed: 0, truncated: false }));\n',
    );
    const f = await fixture('plan.pdf', makeSyntheticPdf('Env'));
    const previous = process.env.AULA_MCP_KEY;
    process.env.AULA_MCP_KEY = 'synthetic-key-must-not-leak';
    try {
      const r = await extractPdfText(f.path, f.size, limits, { workerPath: spy });
      expect(r.ok).toBe(true);
      if (r.ok) {
        expect(r.text).not.toContain('AULA_MCP_KEY');
        expect(r.text.split(',')).toEqual(expect.arrayContaining(['PATH', 'HOME', 'NODE_ENV']));
      }
    } finally {
      if (previous === undefined) delete process.env.AULA_MCP_KEY;
      else process.env.AULA_MCP_KEY = previous;
    }
  });
});

describe('pdfLimitsFromEnv', () => {
  test('uses defaults when unset and ignores nonsense', () => {
    expect(pdfLimitsFromEnv({})).toEqual(DEFAULT_PDF_LIMITS);
    expect(
      pdfLimitsFromEnv({ AULA_MCP_PDF_MAX_PAGES: '-3', AULA_MCP_PDF_TIMEOUT_MS: 'abc' }),
    ).toEqual(DEFAULT_PDF_LIMITS);
  });

  test('honours explicit positive integers', () => {
    expect(
      pdfLimitsFromEnv({
        AULA_MCP_PDF_MAX_BYTES: '1000',
        AULA_MCP_PDF_MAX_PAGES: '3',
        AULA_MCP_PDF_MAX_CHARS: '500',
        AULA_MCP_PDF_TIMEOUT_MS: '1500',
      }),
    ).toEqual({ maxBytes: 1000, maxPages: 3, maxChars: 500, timeoutMs: 1500 });
  });
});
