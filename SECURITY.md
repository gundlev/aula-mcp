# Security policy

This project handles MitID authentication tokens for Danish parents accessing their children's Aula school accounts. Compromise of these tokens grants full read access to a family's school messages, calendar, and presence data — and, depending on `step-up` state, sensitive messages too. Take that seriously.

## Reporting a vulnerability

Email **info@casperjuel.dk** privately. Do **not** open a public GitHub issue for anything that touches token handling, the MitID flow, or wire-trace sanitisation — wait until a fix is shipped.

Include:

- a description of the issue and its impact,
- steps to reproduce (a sanitised wire transcript from `~/.config/aula-mcp/transcripts/` is ideal — see the README on `--debug`),
- the commit SHA you tested against.

We aim to acknowledge within 72 hours and ship a fix within **30 days** unless mutually agreed otherwise.

## Scope

In scope:

- the MitID auth flow in `@aula-mcp/aula-auth` (SRP, OAuth/SAML chain, flowValueProof signing),
- token storage in `EncryptedFileTokenStore` (encryption, key resolution, on-disk permissions),
- wire-trace sanitisation in `wire-tracer.ts` (`SECRET_HEADERS`, `SECRET_BODY_FIELDS`, `SECRET_URL_PARAMS`),
- the MCP server transport in `@aula-mcp/mcp-server` (Hono + `WebStandardStreamableHTTPServerTransport`).

Out of scope:

- vulnerabilities in MitID itself or `nemlog-in.dk` — report those to [nemlog-in.dk](https://www.nemlog-in.dk/),
- vulnerabilities in the Aula platform itself — report those to KOMBIT / the school operator,
- third-party widget providers (EasyIQ, Meebook, Min Uddannelse, Systematic) — report directly to the vendor.

## What we already do

- Tokens are AES-256-GCM-encrypted at rest (`~/.config/aula-mcp/tokens.json`, mode `0600`).
- The encryption key is resolved from an explicit Buffer, then `AULA_MCP_KEY`, then a generated key file (`chmod 600`). The README documents which is strongest.
- Wire-trace transcripts are opt-in (`--debug`), mode `0600`, size-capped, and redact known-secret headers (including `Location`/`Referer`), HTML form fields, JWTs, body fields, and URL query parameters before any line is written. Redaction is best-effort — do not treat a transcript as automatically safe to share.
- The HTTP MCP server requires `Authorization: Bearer <AULA_MCP_AUTH_TOKEN>` unless `AULA_MCP_AUTH=none` is set on a loopback bind. `AULA_MCP_ALLOW_REMOTE=1` is not authentication. Host and Origin headers are validated. Legacy `/sse` is off unless `AULA_MCP_LEGACY_SSE=1`.
- Attachment downloads resolve URLs server-side from Aula data, require HTTPS on an allow-listed host, pin DNS to a public address, and never accept a caller-supplied URL. PDF text extraction only accepts opaque attachment ids.
- The MCP server binds to `127.0.0.1` by default.
- No headless browser is used for MitID — the dependency footprint is auditable.

## What we do not promise

- No formal threat model or external audit yet. v0.1.
- No OS-keychain integration in v0.1 — the file-key fallback is the default, and you should treat the host machine as a trust boundary.
