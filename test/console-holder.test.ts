import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/keys.js';
import { HomeNode } from '../src/server.js';
import { makeEnrollRequest, makeTokenRequest } from '../src/statements.js';
import { mintToken, verifyToken } from '../src/token.js';

function startTestNode(audiences: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), 'hn-holder-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify(audiences));
  copyFileSync(join(import.meta.dirname, '..', 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));
  return new HomeNode({
    iss: 'id.test',
    publicUrl: 'https://id.test',
    bind: '127.0.0.1',
    port: 0,
    dataDir: dir,
    configDir: dir,
  });
}

test('the console refuses non-person tokens with 401 and disabled accounts with 403', async () => {
  const node = startTestNode({ eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] } });
  const base = `http://127.0.0.1:${await node.start()}`;
  const now = Math.floor(Date.now() / 1000);
  try {
    const agentTok = mintToken(node.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'agent:seed@guest',
      kind: 'agent',
      name: 'Seed',
      aud: 'console',
      scopes: ['worlds:join'],
      iat: now,
      exp: now + 600,
    });
    for (const [method, path, body] of [
      ['GET', '/console/me', undefined],
      ['GET', '/console/invites', undefined],
      ['POST', '/console/invites', { label: 'child' }],
    ] as const) {
      const r = await fetch(`${base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${agentTok}`,
          'x-real-ip': '198.51.100.10',
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      assert.equal(r.status, 401, `${method} ${path}`);
      assert.deepEqual(await r.json(), { error: 'not a person' });
    }

    node.accounts.add({
      sub: 'human:local:sponsor',
      username: 'sponsor',
      scopes: ['worlds:join'],
      createdAt: '2026-11-15T00:00:00Z',
    });
    const personTok = mintToken(node.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'human:local:sponsor',
      kind: 'human',
      name: 'sponsor',
      aud: 'console',
      scopes: ['worlds:join'],
      iat: now,
      exp: now + 600,
    });
    const before = await fetch(`${base}/console/me`, {
      headers: { authorization: `Bearer ${personTok}`, 'x-real-ip': '198.51.100.11' },
    });
    assert.equal(before.status, 200);

    node.accounts.update('human:local:sponsor', (a) => ({ ...a, disabled: true }));
    for (const [method, path, body] of [
      ['GET', '/console/me', undefined],
      ['POST', '/console/invites', { label: 'after disable' }],
    ] as const) {
      const r = await fetch(`${base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${personTok}`,
          'x-real-ip': '198.51.100.12',
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      assert.equal(r.status, 403, `${method} ${path}`);
      assert.deepEqual(await r.json(), { error: 'account disabled' });
    }
  } finally {
    node.stop();
  }
});

test('POST /token refuses a listed console or account with 403, and an unlisted node audience still gets 400', async () => {
  const node = startTestNode({
    console: { redirect: 'https://id.test/console' },
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
  });
  const agent = generateKey();
  node.principals.add({
    sub: 'agent:fable@id.test',
    name: 'Fable',
    kind: 'agent',
    key: agent.id,
    scopes: ['worlds:join'],
  });
  const base = `http://127.0.0.1:${await node.start()}`;
  try {
    const listed = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.20' },
      body: JSON.stringify(makeTokenRequest(agent.privateKey, agent.id, 'id.test', 'console')),
    });
    assert.equal(listed.status, 403);
    assert.deepEqual(await listed.json(), { error: 'audience not allowed' });

    const unlisted = await fetch(`${base}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.21' },
      body: JSON.stringify(makeTokenRequest(agent.privateKey, agent.id, 'id.test', 'account')),
    });
    assert.equal(unlisted.status, 400);
    assert.deepEqual(await unlisted.json(), { error: 'unknown audience' });
  } finally {
    node.stop();
  }

  const node2 = startTestNode({
    account: { redirect: 'https://id.test/account' },
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
  });
  node2.principals.add({
    sub: 'agent:fable@id.test',
    name: 'Fable',
    kind: 'agent',
    key: agent.id,
    scopes: ['worlds:join'],
  });
  const base2 = `http://127.0.0.1:${await node2.start()}`;
  try {
    const listedAcct = await fetch(`${base2}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.22' },
      body: JSON.stringify(makeTokenRequest(agent.privateKey, agent.id, 'id.test', 'account')),
    });
    assert.equal(listedAcct.status, 403);
    assert.deepEqual(await listedAcct.json(), { error: 'audience not allowed' });
  } finally {
    node2.stop();
  }
});

test('POST /enroll skips node audiences and refuses an invite listing only node audiences without writing', async () => {
  const node = startTestNode({
    console: { redirect: 'https://id.test/console' },
    account: { redirect: 'https://id.test/account' },
    eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
  });
  const base = `http://127.0.0.1:${await node.start()}`;
  try {
    node.invites.mint({ code: 'inv_unlisted', scopes: ['worlds:join'], maxUses: 1 });
    const k1 = generateKey();
    const r1 = await fetch(`${base}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.30' },
      body: JSON.stringify(makeEnrollRequest(k1.privateKey, k1.id, 'id.test', 'inv_unlisted', 'One')),
    });
    assert.equal(r1.status, 200);
    const b1 = (await r1.json()) as { token: string };
    assert.ok(verifyToken(b1.token, { issuerId: node.issuer.id, iss: 'id.test', aud: 'eidoverse' }).ok);

    node.invites.mint({ code: 'inv_mixed', scopes: ['worlds:join'], audiences: ['console', 'eidoverse'], maxUses: 1 });
    const k2 = generateKey();
    const r2 = await fetch(`${base}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.31' },
      body: JSON.stringify(makeEnrollRequest(k2.privateKey, k2.id, 'id.test', 'inv_mixed', 'Two')),
    });
    assert.equal(r2.status, 200);
    const b2 = (await r2.json()) as { token: string };
    assert.ok(verifyToken(b2.token, { issuerId: node.issuer.id, iss: 'id.test', aud: 'eidoverse' }).ok);

    node.invites.mint({ code: 'inv_node_only', scopes: ['worlds:join'], audiences: ['console', 'account'], maxUses: 1 });
    const k3 = generateKey();
    const r3 = await fetch(`${base}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.32' },
      body: JSON.stringify(makeEnrollRequest(k3.privateKey, k3.id, 'id.test', 'inv_node_only', 'Three')),
    });
    assert.equal(r3.status, 400);
    assert.match(String(((await r3.json()) as { error: string }).error), /ask for a new one/);
    assert.equal(node.principals.byKey(k3.id), undefined);
    assert.equal(typeof node.invites.check('inv_node_only'), 'object');
  } finally {
    node.stop();
  }
});
