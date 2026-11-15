import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import { HomeNode } from '../src/server.js';
import { mintToken } from '../src/token.js';

function makeConsoleNode(iss = 'id.test') {
  const dir = mkdtempSync(join(tmpdir(), 'hn-con-page-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({ eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] } }));
  copyFileSync(join(import.meta.dirname, '..', 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));
  return new HomeNode({
    iss,
    publicUrl: 'https://id.test',
    bind: '127.0.0.1',
    port: 0,
    dataDir: dir,
    configDir: dir,
  });
}

test('GET /console sends the credential-page CSP with a matching script nonce and escapes the title', async () => {
  const node = makeConsoleNode('id.test</title><x>&"');
  const base = `http://127.0.0.1:${await node.start()}`;
  try {
    const r = await fetch(`${base}/console`, { headers: { 'x-real-ip': '198.51.100.50' } });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(r.headers.get('cache-control'), 'no-store');
    const csp = r.headers.get('content-security-policy') ?? '';
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    const m = /script-src 'nonce-([A-Za-z0-9+/=]+)'/.exec(csp);
    assert.ok(m, `missing script nonce in CSP: ${csp}`);
    const body = await r.text();
    assert.ok(body.includes(`<script nonce="${m[1]}">`), 'script tag must carry the response nonce');
    assert.ok(body.includes('<title>agent invites — id.test&lt;/title&gt;&lt;x&gt;&amp;&quot;</title>'));
  } finally {
    node.stop();
  }
});

test('the console client script escapes every rendered field while storing invite labels verbatim', async () => {
  const node = makeConsoleNode('id.test');
  const base = `http://127.0.0.1:${await node.start()}`;
  const now = Math.floor(Date.now() / 1000);
  try {
    const rawLabel = '<img src=x onerror="1">';
    const tok = mintToken(node.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'human:discord:9001',
      kind: 'human',
      name: '<b>Mallory</b>',
      aud: 'console',
      scopes: ['worlds:join', 'id:anchor'],
      iat: now,
      exp: now + 600,
    });
    const mintRes = await fetch(`${base}/console/invites`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json', 'x-real-ip': '198.51.100.51' },
      body: JSON.stringify({ label: rawLabel }),
    });
    assert.equal(mintRes.status, 200);
    assert.equal(node.invites.all()[0]?.label, rawLabel);

    const html = await (await fetch(`${base}/console`, { headers: { 'x-real-ip': '198.51.100.52' } })).text();
    const scriptMatch = /<script[^>]*>([\s\S]*?)<\/script>/.exec(html);
    assert.ok(scriptMatch);

    const els: Record<string, { innerHTML: string; value: string; checked: boolean; onclick?: () => Promise<void> }> = {
      app: { innerHTML: '', value: '', checked: false },
      label: { innerHTML: '', value: 'plain', checked: false },
      anchor: { innerHTML: '', value: '', checked: false },
      mint: { innerHTML: '', value: '', checked: false },
      minted: { innerHTML: '', value: '', checked: false },
    };
    let doneResolve!: () => void;
    const done = new Promise<void>((r) => { doneResolve = r; });

    const sandbox = {
      URLSearchParams,
      location: { hash: `#token=${tok}` },
      history: { replaceState: () => {} },
      document: {
        getElementById: (id: string) => els[id],
      },
      fetch: async (path: string, opts?: { method?: string }) => {
        if (path === '/console/me') {
          return {
            status: 200,
            json: async () => ({
              sub: 'human:discord:<sub-tag>',
              name: '<img src=x onerror="name">',
              delegable: ['worlds:join', '<scope>'],
              canAnchor: true,
              home: 'id.test<home>',
              residentScopes: ['<res>'],
            }),
          };
        }
        if (path === '/console/invites' && (!opts?.method || opts.method === 'GET')) {
          setImmediate(doneResolve);
          return {
            status: 200,
            json: async () => ({
              invites: [
                {
                  code: 'inv_<code>',
                  label: rawLabel,
                  status: 'claimed<st>',
                  expiresAt: '2026-11-<d>',
                  agent: { name: '<svg onload=1>', sub: 'agent:<sub2>' },
                },
              ],
            }),
          };
        }
        return {
          status: 403,
          json: async () => ({ error: '<script>bad</script>' }),
        };
      },
    };
    vm.runInNewContext(scriptMatch[1]!, sandbox);
    await done;
    assert.ok(!els.app.innerHTML.includes('<img'), `unescaped <img> in app.innerHTML: ${els.app.innerHTML}`);
    assert.ok(!els.app.innerHTML.includes('<svg'), `unescaped <svg> in app.innerHTML: ${els.app.innerHTML}`);
    assert.ok(els.app.innerHTML.includes('&lt;img src=x onerror=&quot;1&quot;&gt;'));

    await els.mint.onclick!();
    assert.ok(!els.minted.innerHTML.includes('<script>'), `unescaped error in minted.innerHTML: ${els.minted.innerHTML}`);
    assert.ok(els.minted.innerHTML.includes('&lt;script&gt;bad&lt;/script&gt;'));
  } finally {
    node.stop();
  }
});
