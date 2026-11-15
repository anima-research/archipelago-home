import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/keys.js';
import { HomeNode } from '../src/server.js';
import { makeEnrollRequest, makeTokenRequest } from '../src/statements.js';
import { mintToken, verifyToken } from '../src/token.js';

function startTestNode(audiences: Record<string, unknown>, policyOverride?: unknown) {
  const dir = mkdtempSync(join(tmpdir(), 'hn-holder-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify(audiences));
  if (policyOverride !== undefined) {
    writeFileSync(join(dir, 'invite-policy.json'), JSON.stringify(policyOverride));
  } else {
    copyFileSync(join(import.meta.dirname, '..', 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));
  }
  return new HomeNode({
    iss: 'id.test',
    publicUrl: 'https://id.test',
    bind: '127.0.0.1',
    port: 0,
    dataDir: dir,
    configDir: dir,
  });
}

test('the console refuses non-person tokens with 401, disabled accounts with 403, and Discord-only tokens whose Discord id was linked elsewhere with 401', async () => {
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

    const discordOnlyTok = mintToken(node.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'human:discord:5555',
      kind: 'human',
      name: 'DiscordOnly',
      aud: 'console',
      scopes: ['worlds:join'],
      iat: now,
      exp: now + 600,
    });
    const dcBefore = await fetch(`${base}/console/me`, {
      headers: { authorization: `Bearer ${discordOnlyTok}`, 'x-real-ip': '198.51.100.13' },
    });
    assert.equal(dcBefore.status, 200);

    node.accounts.add({
      sub: 'human:local:linked',
      username: 'linked',
      discord: { id: '5555', name: 'DiscordOnly' },
      scopes: ['worlds:join'],
      createdAt: '2026-11-15T00:00:00Z',
    });
    for (const [method, path, body] of [
      ['GET', '/console/me', undefined],
      ['GET', '/console/invites', undefined],
      ['POST', '/console/invites', { label: 'after link' }],
    ] as const) {
      const r = await fetch(`${base}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${discordOnlyTok}`,
          'x-real-ip': '198.51.100.14',
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      assert.equal(r.status, 401, `linked Discord ${method} ${path}`);
      assert.deepEqual(await r.json(), { error: 'this Discord account is now linked to another account here; sign in again' });
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

test('POST /enroll skips node and unregistered audiences, refuses node-only or unregistered-only invites without writing, and names when no agent audience exists', async () => {
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

    node.invites.mint({ code: 'inv_unreg_first', scopes: ['worlds:join'], audiences: ['console', 'misspelled', 'eidoverse'], maxUses: 1 });
    const kUnregFirst = generateKey();
    const rUnregFirst = await fetch(`${base}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.33' },
      body: JSON.stringify(makeEnrollRequest(kUnregFirst.privateKey, kUnregFirst.id, 'id.test', 'inv_unreg_first', 'TwoB')),
    });
    assert.equal(rUnregFirst.status, 200);
    const bUnregFirst = (await rUnregFirst.json()) as { token: string };
    assert.ok(verifyToken(bUnregFirst.token, { issuerId: node.issuer.id, iss: 'id.test', aud: 'eidoverse' }).ok);

    for (const [code, auds, name, ip] of [
      ['inv_node_only', ['console', 'account'], 'Three', '198.51.100.32'],
      ['inv_unreg_only', ['misspelled'], 'Four', '198.51.100.34'],
    ] as const) {
      node.invites.mint({ code, scopes: ['worlds:join'], audiences: [...auds], maxUses: 1 });
      const k = generateKey();
      const r = await fetch(`${base}/enroll`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-real-ip': ip },
        body: JSON.stringify(makeEnrollRequest(k.privateKey, k.id, 'id.test', code, name)),
      });
      assert.equal(r.status, 400, code);
      assert.match(String(((await r.json()) as { error: string }).error), /ask for a new one/);
      assert.equal(node.principals.byKey(k.id), undefined);
      assert.equal(typeof node.invites.check(code), 'object');
    }
  } finally {
    node.stop();
  }

  const nodeOnlyConsole = startTestNode({
    console: { redirect: 'https://id.test/console' },
  });
  const baseOnlyConsole = `http://127.0.0.1:${await nodeOnlyConsole.start()}`;
  try {
    nodeOnlyConsole.invites.mint({ code: 'inv_any', scopes: ['worlds:join'], maxUses: 1 });
    const kAny = generateKey();
    const rAny = await fetch(`${baseOnlyConsole}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.35' },
      body: JSON.stringify(makeEnrollRequest(kAny.privateKey, kAny.id, 'id.test', 'inv_any', 'Five')),
    });
    assert.equal(rAny.status, 400);
    assert.deepEqual(await rAny.json(), { error: 'this node has no audience for agents — ask whoever runs it' });
    assert.equal(nodeOnlyConsole.principals.byKey(kAny.id), undefined);
    assert.equal(typeof nodeOnlyConsole.invites.check('inv_any'), 'object');
  } finally {
    nodeOnlyConsole.stop();
  }
});

test('POST /console/invites rechecks the holder after the body ends and refuses policies that grant only node audiences', async () => {
  const node = startTestNode({ eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] } });
  const port = await node.start();
  const now = Math.floor(Date.now() / 1000);
  try {
    node.accounts.add({
      sub: 'human:local:inflight',
      username: 'inflight',
      scopes: ['worlds:join'],
      createdAt: '2026-11-15T00:00:00Z',
    });
    const inflightTok = mintToken(node.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'human:local:inflight',
      kind: 'human',
      name: 'inflight',
      aud: 'console',
      scopes: ['worlds:join'],
      iat: now,
      exp: now + 600,
    });

    const origBySub = node.accounts.bySub.bind(node.accounts);
    let resolveFirstAuth!: () => void;
    const firstAuthDone = new Promise<void>((r) => { resolveFirstAuth = r; });
    let seenFirst = false;
    node.accounts.bySub = (sub: string) => {
      const res = origBySub(sub);
      if (sub === 'human:local:inflight' && !seenFirst) {
        seenFirst = true;
        setImmediate(resolveFirstAuth);
      }
      return res;
    };

    const payload = '{"label":"slow"}';
    const part1 = payload.slice(0, 9);
    const part2 = payload.slice(9);
    const rawResp = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      const sock = createConnection({ host: '127.0.0.1', port }, () => {
        sock.write(
          `POST /console/invites HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${inflightTok}\r\n` +
            `X-Real-IP: 198.51.100.40\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(payload)}\r\n` +
            `Connection: close\r\n\r\n${part1}`,
        );
      });
      firstAuthDone.then(() => {
        node.accounts.update('human:local:inflight', (a) => ({ ...a, disabled: true }));
        sock.write(part2);
      }, reject);
      sock.on('data', (c: Buffer) => chunks.push(c));
      sock.on('error', reject);
      sock.on('close', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });

    assert.match(rawResp, /^HTTP\/1\.1 403\b/);
    assert.match(rawResp, /"account disabled"/);
    assert.equal(node.invites.all().length, 0);
  } finally {
    node.stop();
  }

  const nodeConsoleOnlyPolicy = startTestNode(
    {
      console: { redirect: 'https://id.test/console' },
      eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] },
    },
    {
      console: { requiredScopes: ['worlds:join'] },
      primaryAudience: 'console',
      scopes: {
        'worlds:join': ['delegable', 'resident'],
      },
      audiences: [{ audience: 'console', always: true }],
    },
  );
  const basePolicy = `http://127.0.0.1:${await nodeConsoleOnlyPolicy.start()}`;
  try {
    const sponsorTok = mintToken(nodeConsoleOnlyPolicy.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'human:discord:7777',
      kind: 'human',
      name: 'PolicySponsor',
      aud: 'console',
      scopes: ['worlds:join'],
      iat: now,
      exp: now + 600,
    });
    const rMint = await fetch(`${basePolicy}/console/invites`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${sponsorTok}`,
        'content-type': 'application/json',
        'x-real-ip': '198.51.100.41',
      },
      body: JSON.stringify({ label: 'useless' }),
    });
    assert.equal(rMint.status, 403);
    assert.match(String(((await rMint.json()) as { error: string }).error), /only the node's own audiences, which no agent can hold/);
    assert.equal(nodeConsoleOnlyPolicy.invites.all().length, 0);
  } finally {
    nodeConsoleOnlyPolicy.stop();
  }
});
