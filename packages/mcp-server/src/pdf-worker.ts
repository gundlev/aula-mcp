/**
 * PDF text extraction worker. Runs as a separate Bun process spawned by
 * `pdf-extract.ts` so a hostile or merely enormous PDF can be killed on a
 * deadline without taking the MCP server down with it, and so pdf.js's
 * memory use is not the server's.
 *
 * argv: <path> <limits-json>
 * stdout: one JSON object — `{ ok: true, text, pages, pagesParsed, truncated }`
 *         or `{ ok: false, message }`. Nothing else is ever written to
 *         stdout; the parent parses it as a whole.
 */

import { readFile } from 'node:fs/promises';

interface Limits {
  maxPages: number;
  maxChars: number;
}

interface TextResultLike {
  text: string;
  total: number;
  pages: Array<{ num: number; text: string }>;
}

async function main(): Promise<void> {
  const [path, limitsRaw] = process.argv.slice(2);
  if (!path || !limitsRaw) throw new Error('usage: pdf-worker <path> <limits-json>');
  const limits = JSON.parse(limitsRaw) as Limits;
  const data = await readFile(path);
  if (!data.subarray(0, 1024).includes('%PDF-')) throw new Error('not a PDF file');

  const { PDFParse } = (await import('pdf-parse')) as unknown as {
    PDFParse: new (
      opts: Record<string, unknown>,
    ) => {
      getText(params?: { first?: number }): Promise<TextResultLike>;
      destroy?(): Promise<void>;
    };
  };
  const parser = new PDFParse({
    data,
    // pdf.js can evaluate PostScript calculator functions through `eval`;
    // an attachment must never get that.
    isEvalSupported: false,
    // We only want text — never decode images.
    maxImageSize: 1,
    disableFontFace: true,
    stopAtErrors: false,
  });
  try {
    const result = await parser.getText({ first: limits.maxPages });
    let text = result.text;
    let truncated = false;
    if (text.length > limits.maxChars) {
      text = text.slice(0, limits.maxChars);
      truncated = true;
    }
    if (result.total > limits.maxPages) truncated = true;
    process.stdout.write(
      JSON.stringify({
        ok: true,
        text,
        pages: result.total,
        pagesParsed: Math.min(result.pages.length, limits.maxPages),
        truncated,
      }),
    );
  } finally {
    if (parser.destroy) await parser.destroy();
  }
}

main().catch((e: unknown) => {
  const message = e instanceof Error ? e.message : String(e);
  process.stdout.write(JSON.stringify({ ok: false, message: message.slice(0, 500) }));
  process.exitCode = 1;
});
