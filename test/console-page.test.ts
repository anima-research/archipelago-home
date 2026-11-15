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
    const rawLabel = '<label-tag "q">';
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
    let postStep: 'ok' | 'err' = 'ok';

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
              name: '<name-tag>',
              delegable: ['worlds:join', '<deleg-tag>'],
              canAnchor: true,
              home: 'id.test<home-tag>',
              residentScopes: ['<res-tag>'],
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
                  code: 'inv_<code-tag>',
                  label: rawLabel,
                  status: 'claimed<status-tag>',
                  expiresAt: '<i>2026-11-30T00:00:00Z',
                  agent: { name: '<agent-name>', sub: 'agent:<agent-sub>' },
                },
              ],
            }),
          };
        }
        if (postStep === 'ok') {
          return {
            status: 200,
            json: async () => ({ invite: { code: 'inv_<mint-code>' } }),
          };
        }
        return {
          status: 403,
          json: async () => ({ error: '<err-tag>' }),
        };
      },
    };
    vm.runInNewContext(scriptMatch[1]!, sandbox);
    await done;

    const appPairs: Array<[string, string]> = [
      ['inv_<code-tag>', 'inv_&lt;code-tag&gt;'],
      [rawLabel, '&lt;label-tag &quot;q&quot;&gt;'],
      ['claimed<status-tag>', 'claimed&lt;status-tag&gt;'],
      ['<i>2026-11', '&lt;i&gt;2026-11'],
      ['<agent-name>', '&lt;agent-name&gt;'],
      ['agent:<agent-sub>', 'agent:&lt;agent-sub&gt;'],
      ['<name-tag>', '&lt;name-tag&gt;'],
      ['human:discord:<sub-tag>', 'human:discord:&lt;sub-tag&gt;'],
      ['<deleg-tag>', '&lt;deleg-tag&gt;'],
      ['id.test<home-tag>', 'id.test&lt;home-tag&gt;'],
      ['<res-tag>', '&lt;res-tag&gt;'],
    ];
    for (const [raw, escaped] of appPairs) {
      assert.ok(!els.app.innerHTML.includes(raw), `unescaped ${raw} in app.innerHTML`);
      assert.ok(els.app.innerHTML.includes(escaped), `missing escaped ${escaped} in app.innerHTML`);
    }

    postStep = 'ok';
    await els.mint.onclick!();
    assert.ok(!els.minted.innerHTML.includes('inv_<mint-code>'));
    assert.ok(els.minted.innerHTML.includes('inv_&lt;mint-code&gt;'));

    postStep = 'err';
    await els.mint.onclick!();
    assert.ok(!els.minted.innerHTML.includes('<err-tag>'));
    assert.ok(els.minted.innerHTML.includes('&lt;err-tag&gt;'));
  } finally {
    node.stop();
  }
});
