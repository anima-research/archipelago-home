/** Tiny HTTP helpers shared by the routes (plain node:http, no framework). */
import { MARK, STYLE } from './site.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';

const BODY_LIMIT = 64 * 1024;

export function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

export function html(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(body);
}

export function redirect(res: ServerResponse, to: string): void {
  res.writeHead(302, { location: to });
  res.end();
}

/**
 * A page that handles credentials: inline script allowed only by nonce, no
 * framing (clickjacking), no referrer, no caching, fetch only to this origin.
 * `render` receives the nonce to stamp on its <script>.
 */
export function securePage(res: ServerResponse, status: number, render: (nonce: string) => string): void {
  const nonce = randomBytes(16).toString('base64');
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy':
      `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src 'self' data:; ` +
      `connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'cache-control': 'no-store',
  });
  res.end(render(nonce));
}

/** A short message (a sign-in that failed, a link that expired): the node's look, no script. */
export function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style>
<header class="top"><a class="brand" href="/">${MARK}<span><b>Archipelago</b></span></a><nav aria-label="Main"><a href="/account">Your account</a></nav></header>
<main><div class="card"><h1>${esc(title.charAt(0).toUpperCase() + title.slice(1))}</h1>${body}</div></main></html>`;
}

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > BODY_LIMIT) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export async function readJson(req: IncomingMessage): Promise<unknown> {
  const text = await readBody(req); // too large, or a broken connection: rejects
  try {
    return JSON.parse(text);
  } catch {
    return null; // handlers reject malformed bodies with a reason
  }
}
