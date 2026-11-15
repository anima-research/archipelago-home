import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/keys.js';
import { HomeNode } from '../src/server.js';
import { makeEnrollRequest } from '../src/statements.js';
import { InviteStore, PrincipalStore } from '../src/stores.js';
import { mintToken } from '../src/token.js';

const ROOT = join(import.meta.dirname, '..');

function runHn(dir: string, ...args: string[]) {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, HN_DOMAIN: 'id.test', HN_DATA_DIR: dir, HN_CONFIG_DIR: dir },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test('a CLI invite revocation survives a concurrent console mint before the poll window', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-inv-race-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  writeFileSync(join(dir, 'audiences.json'), JSON.stringify({ eidoverse: { redirect: 'https://worlds.test/auth', requiredScopes: ['worlds:join'] } }));
  copyFileSync(join(ROOT, 'config', 'invite-policy.example.json'), join(dir, 'invite-policy.json'));

  const node = new HomeNode({
    iss: 'id.test',
    publicUrl: 'https://id.test',
    bind: '127.0.0.1',
    port: 0,
    dataDir: dir,
    configDir: dir,
  });
  const base = `http://127.0.0.1:${await node.start()}`;
  const now = Math.floor(Date.now() / 1000);
  try {
    const sponsorTok = mintToken(node.issuer.privateKey, {
      v: 1,
      iss: 'id.test',
      sub: 'human:discord:9400',
      kind: 'human',
      name: 'Sponsor',
      aud: 'console',
      scopes: ['worlds:join'],
      iat: now,
      exp: now + 600,
    });
    const m1 = await fetch(`${base}/console/invites`, {
      method: 'POST',
      headers: { authorization: `Bearer ${sponsorTok}`, 'content-type': 'application/json', 'x-real-ip': '198.51.100.40' },
      body: JSON.stringify({ label: 'first' }),
    });
    assert.equal(m1.status, 200);
    const codeA = ((await m1.json()) as { invite: { code: string } }).invite.code;

    const rev = runHn(dir, 'revoke-invite', codeA);
    assert.equal(rev.status, 0, rev.stderr);

    const m2 = await fetch(`${base}/console/invites`, {
      method: 'POST',
      headers: { authorization: `Bearer ${sponsorTok}`, 'content-type': 'application/json', 'x-real-ip': '198.51.100.41' },
      body: JSON.stringify({ label: 'second' }),
    });
    assert.equal(m2.status, 200);
    const codeB = ((await m2.json()) as { invite: { code: string } }).invite.code;

    const diskCodes = (JSON.parse(readFileSync(join(dir, 'invites.json'), 'utf8')) as { invites: Array<{ code: string }> }).invites.map((i) => i.code);
    assert.ok(!diskCodes.includes(codeA), 'revoked invite A must not come back on disk');
    assert.ok(diskCodes.includes(codeB));

    const stranger = generateKey();
    const enrollRevoked = await fetch(`${base}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.42' },
      body: JSON.stringify(makeEnrollRequest(stranger.privateKey, stranger.id, 'id.test', codeA, 'Lazarus')),
    });
    assert.equal(enrollRevoked.status, 403);
  } finally {
    node.stop();
  }
});

test('PrincipalStore and InviteStore preserve another writer changes and check duplicates against disk', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-two-writers-'));
  const pPath = join(dir, 'principals.json');
  const p1 = new PrincipalStore(pPath);
  const p2 = new PrincipalStore(pPath);

  p1.add({ sub: 'agent:alpha@guest', name: 'Alpha', kind: 'agent', key: 'ed25519:key1', scopes: ['worlds:join'] });
  assert.equal(p2.revoke('agent:alpha@guest', '2026-11-15T00:00:00Z'), true);
  p1.add({ sub: 'agent:beta@guest', name: 'Beta', kind: 'agent', key: 'ed25519:key2', scopes: ['worlds:join'] });

  const pFresh = new PrincipalStore(pPath);
  assert.equal(pFresh.isLive(pFresh.bySub('agent:alpha@guest')!, Date.parse('2026-11-15T00:01:00Z')), false);
  assert.ok(pFresh.bySub('agent:beta@guest'));

  p2.add({ sub: 'agent:gamma@guest', name: 'Gamma', kind: 'agent', key: 'ed25519:key3', scopes: [] });
  assert.throws(() => p1.add({ sub: 'agent:other@guest', name: 'gamma', kind: 'agent', key: null, scopes: [] }), /already taken/);
  assert.throws(() => p1.add({ sub: 'agent:other2@guest', name: 'Other2', kind: 'agent', key: 'ed25519:key3', scopes: [] }), /key already enrolled/);

  const iPath = join(dir, 'invites.json');
  const i1 = new InviteStore(iPath);
  const i2 = new InviteStore(iPath);
  const a = i1.mint({ code: 'inv_a', scopes: ['worlds:join'], maxUses: 2 });
  i2.mint({ code: 'inv_b', scopes: ['worlds:join'], maxUses: 1 });
  assert.throws(() => i1.mint({ code: 'inv_b', scopes: ['worlds:join'] }), /duplicate invite code/);
  assert.equal(i2.revoke(a.code), true);
  i1.consume(a.code);
  assert.deepEqual(new InviteStore(iPath).all().map((i) => i.code), ['inv_b']);
});

test('bare hn invite defaults to single-use and 72h expiry; open forms are named and bad flags refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-inv-cli-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));

  const before = Date.now();
  const bare = runHn(dir, 'invite', '--scopes', 'worlds:join');
  assert.equal(bare.status, 0, bare.stderr);
  assert.match(bare.stderr, /1 use · ends \d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z/);
  const code = bare.stdout.trim();
  const stored = new InviteStore(join(dir, 'invites.json')).all().find((i) => i.code === code)!;
  assert.equal(stored.maxUses, 1);
  assert.ok(stored.expiresAt);
  const deltaHours = (Date.parse(stored.expiresAt) - before) / 3_600_000;
  assert.ok(deltaHours > 71.9 && deltaHours < 72.1, `expected ~72h, got ${deltaHours}h`);

  const open = runHn(dir, 'invite', '--scopes', 'worlds:join', '--max-uses', 'any', '--expires', 'never');
  assert.equal(open.status, 0, open.stderr);
  assert.match(open.stderr, /any number of uses · no end date/);
  const openInv = new InviteStore(join(dir, 'invites.json')).all().find((i) => i.code === open.stdout.trim())!;
  assert.equal(openInv.maxUses, undefined);
  assert.equal(openInv.expiresAt, undefined);

  const snap = readFileSync(join(dir, 'invites.json'), 'utf8');
  for (const bad of [
    ['--max-uses', 'foo'],
    ['--max-uses', '0'],
    ['--max-uses', '1.5'],
    ['--expires', 'soon'],
    ['--expires', '72'],
  ]) {
    const r = runHn(dir, 'invite', '--scopes', 'worlds:join', ...bad);
    assert.notEqual(r.status, 0, bad.join(' '));
    assert.equal(readFileSync(join(dir, 'invites.json'), 'utf8'), snap);
  }
});
