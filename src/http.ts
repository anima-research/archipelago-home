/** Tiny HTTP helpers shared by the routes (plain node:http, no framework). */
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

export function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>body{font:16px/1.5 system-ui;max-width:36rem;margin:15vh auto;padding:0 1rem;color:#222}
code{background:#f2f2f2;padding:.1em .3em;border-radius:4px;word-break:break-all}
@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}code{background:#222}}</style>
<h2>${esc(title)}</h2>${body}`;
}

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

export function readJson(req: IncomingMessage): Promise<unknown> {
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
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        resolve(null); // handlers reject malformed bodies with a reason
      }
    });
    req.on('error', reject);
  });
}
