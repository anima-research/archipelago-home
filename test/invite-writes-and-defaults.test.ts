import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, statSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { handleEnroll } from '../src/exchange.js';
import { generateKey, loadOrCreateIssuerKey } from '../src/keys.js';
import { HomeNode } from '../src/server.js';
import { makeEnrollRequest } from '../src/statements.js';
import { InviteStore, MintLog, PrincipalStore } from '../src/stores.js';
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
  node.invites.stopWatching();
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

test("PrincipalStore and InviteStore preserve another writer's changes and check duplicates against disk", () => {
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

  const pNameStale = new PrincipalStore(pPath);
  const pKeyStale = new PrincipalStore(pPath);
  const pSubStale = new PrincipalStore(pPath);
  pNameStale.all();
  pKeyStale.all();
  pSubStale.all();

  p2.add({ sub: 'agent:gamma@guest', name: 'Gamma', kind: 'agent', key: 'ed25519:key3', scopes: [] });
  assert.throws(() => pNameStale.add({ sub: 'agent:other@guest', name: 'gamma', kind: 'agent', key: null, scopes: [] }), /already taken/);
  assert.throws(() => pKeyStale.add({ sub: 'agent:other2@guest', name: 'Other2', kind: 'agent', key: 'ed25519:key3', scopes: [] }), /key already enrolled/);
  assert.throws(() => pSubStale.add({ sub: 'agent:gamma@guest', name: 'Other3', kind: 'agent', key: null, scopes: [] }), /duplicate sub agent:gamma@guest/);

  const iPath = join(dir, 'invites.json');
  const i1 = new InviteStore(iPath);
  const i2 = new InviteStore(iPath);
  const a = i1.mint({ code: 'inv_a', scopes: ['worlds:join'], maxUses: 2 });
  i2.mint({ code: 'inv_b', scopes: ['worlds:join'], maxUses: 1 });
  assert.throws(() => i1.mint({ code: 'inv_b', scopes: ['worlds:join'] }), /duplicate invite code/);
  assert.equal(i2.revoke(a.code), true);
  const past = new Date(1_700_000_000_000);
  utimesSync(iPath, past, past);
  const beforeMtime = statSync(iPath).mtimeMs;
  const beforeBytes = readFileSync(iPath, 'utf8');
  assert.equal(i1.consume(a.code), 'unknown');
  assert.equal(statSync(iPath).mtimeMs, beforeMtime);
  assert.equal(readFileSync(iPath, 'utf8'), beforeBytes);
  assert.deepEqual(new InviteStore(iPath).all().map((i) => i.code), ['inv_b']);
  i2.mint({ code: 'inv_c', scopes: ['worlds:join'], maxUses: 1 });
  assert.equal(i1.revoke('inv_c'), true);
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
  for (const [args, pattern] of [
    [['--max-uses', 'foo'], /--max-uses wants a positive whole number, or any/],
    [['--max-uses', '0'], /--max-uses wants a positive whole number, or any/],
    [['--max-uses', '1.5'], /--max-uses wants a positive whole number, or any/],
    [['--expires', 'soon'], /--expires wants a lifetime \(72h, 14d\), a date \(2026-12-01\), or never/],
    [['--expires', '72'], /--expires wants a lifetime \(72h, 14d\), a date \(2026-12-01\), or never/],
  ] as const) {
    const r = runHn(dir, 'invite', '--scopes', 'worlds:join', ...args);
    assert.equal(r.status, 1, args.join(' '));
    assert.match(r.stderr, pattern);
    assert.equal(readFileSync(join(dir, 'invites.json'), 'utf8'), snap);
  }
});

test('hn invite keeps a use count, a lifetime and a date that are given', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-inv-cli-'));
  writeFileSync(join(dir, 'principals.json'), JSON.stringify({ principals: [] }));
  const stored = (code: string) => new InviteStore(join(dir, 'invites.json')).all().find((i) => i.code === code)!;

  const before = Date.now();
  const counted = runHn(dir, 'invite', '--scopes', 'worlds:join', '--max-uses', '3', '--expires', '14d');
  assert.equal(counted.status, 0, counted.stderr);
  assert.match(counted.stderr, /3 uses · ends /);
  const c = stored(counted.stdout.trim());
  assert.equal(c.maxUses, 3);
  const days = (Date.parse(c.expiresAt!) - before) / 86_400_000;
  assert.ok(days > 13.99 && days < 14.01, `expected ~14d, got ${days}d`);

  const dated = runHn(dir, 'invite', '--scopes', 'worlds:join', '--expires', '2099-01-01');
  assert.equal(dated.status, 0, dated.stderr);
  const d = stored(dated.stdout.trim());
  assert.equal(Date.parse(d.expiresAt!), Date.parse('2099-01-01T00:00:00Z'));
  assert.equal(d.maxUses, 1);
});

test('enrollment spends the invite under its lock before adding the principal, maps races to 403, and throws on unreadable files', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-enroll-lock-'));
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
  node.invites.stopWatching();
  node.principals.stopWatching();
  try {
    const lockedInv = node.invites.mint({ code: 'inv_locked', scopes: ['worlds:join'], maxUses: 1 });
    const kLocked = generateKey();
    const lockPath = join(dir, 'invites.json.lock');
    writeFileSync(lockPath, 'held');
    try {
      const rLocked = await fetch(`${base}/enroll`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.60' },
        body: JSON.stringify(makeEnrollRequest(kLocked.privateKey, kLocked.id, 'id.test', lockedInv.code, 'Waiter')),
      });
      assert.equal(rLocked.status, 500);
      const onDiskAfterTimeout = JSON.parse(readFileSync(join(dir, 'principals.json'), 'utf8')) as { principals: unknown[] };
      assert.equal(onDiskAfterTimeout.principals.length, 0);
    } finally {
      try { unlinkSync(lockPath); } catch {}
    }

    const rAfterRelease = await fetch(`${base}/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': '198.51.100.61' },
      body: JSON.stringify(makeEnrollRequest(kLocked.privateKey, kLocked.id, 'id.test', lockedInv.code, 'Waiter')),
    });
    assert.equal(rAfterRelease.status, 200);
  } finally {
    node.stop();
  }

  const raceDir = mkdtempSync(join(tmpdir(), 'hn-enroll-races-'));
  const issuer = loadOrCreateIssuerKey(join(raceDir, 'issuer-key.pem'));
  const pPath = join(raceDir, 'principals.json');
  const iPath = join(raceDir, 'invites.json');
  const principals = new PrincipalStore(pPath);
  const invites = new InviteStore(iPath);
  const mintLog = new MintLog(join(raceDir, 'minted.jsonl'));

  invites.mint({ code: 'inv_rev_race', scopes: ['worlds:join'], maxUses: 1 });
  const kRev = generateKey();
  const rRevoked = handleEnroll(
    makeEnrollRequest(kRev.privateKey, kRev.id, 'id.test', 'inv_rev_race', 'Latecomer'),
    {
      issuer,
      iss: 'id.test',
      principals,
      invites,
      mintLog,
      knownAudiences: () => {
        new InviteStore(iPath).revoke('inv_rev_race');
        return ['eidoverse'];
      },
    },
  );
  assert.equal(rRevoked.status, 403);
  assert.deepEqual(rRevoked.body, { error: 'invite unknown' });
  assert.equal(new PrincipalStore(pPath).all().length, 0);

  invites.mint({ code: 'inv_name_race', scopes: ['worlds:join'], maxUses: 1 });
  const kName = generateKey();
  const rName = handleEnroll(
    makeEnrollRequest(kName.privateKey, kName.id, 'id.test', 'inv_name_race', 'Racer'),
    {
      issuer,
      iss: 'id.test',
      principals,
      invites,
      mintLog,
      knownAudiences: () => {
        new PrincipalStore(pPath).add({ sub: 'agent:other-racer@guest', name: 'racer', kind: 'agent', key: null, scopes: [] });
        return ['eidoverse'];
      },
    },
  );
  assert.equal(rName.status, 403);
  assert.deepEqual(rName.body, { error: 'name taken' });
  assert.equal(new InviteStore(iPath).all().find((i) => i.code === 'inv_name_race')?.uses ?? 0, 0);

  const kKey = generateKey();
  const rKey = handleEnroll(
    makeEnrollRequest(kKey.privateKey, kKey.id, 'id.test', 'inv_name_race', 'DistinctName'),
    {
      issuer,
      iss: 'id.test',
      principals,
      invites,
      mintLog,
      knownAudiences: () => {
        new PrincipalStore(pPath).add({ sub: 'agent:key-holder@guest', name: 'KeyHolder', kind: 'agent', key: kKey.id, scopes: [] });
        return ['eidoverse'];
      },
    },
  );
  assert.equal(rKey.status, 403);
  assert.deepEqual(rKey.body, { error: 'key already enrolled' });
  assert.equal(new InviteStore(iPath).all().find((i) => i.code === 'inv_name_race')?.uses ?? 0, 0);

  const kSub = generateKey();
  const rSub = handleEnroll(
    makeEnrollRequest(kSub.privateKey, kSub.id, 'id.test', 'inv_name_race', 'slug-race'),
    {
      issuer,
      iss: 'id.test',
      principals,
      invites,
      mintLog,
      knownAudiences: () => {
        new PrincipalStore(pPath).add({ sub: 'agent:slug-race@guest', name: 'slug_race', kind: 'agent', key: null, scopes: [] });
        return ['eidoverse'];
      },
    },
  );
  assert.equal(rSub.status, 403);
  assert.deepEqual(rSub.body, { error: 'name taken' });
  assert.equal(new InviteStore(iPath).all().find((i) => i.code === 'inv_name_race')?.uses ?? 0, 0);

  const brokenDir = mkdtempSync(join(tmpdir(), 'hn-broken-inv-'));
  const brokenPath = join(brokenDir, 'invites.json');
  const iStale = new InviteStore(brokenPath);
  iStale.all();
  new InviteStore(brokenPath).mint({ code: 'inv_broken', scopes: ['worlds:join'], maxUses: 1 });
  writeFileSync(brokenPath, '{corrupt');
  assert.throws(() => iStale.revoke('inv_broken'), /is unreadable or invalid/);
  let admitRan = false;
  assert.throws(
    () => iStale.consume('inv_broken', Date.now(), () => { admitRan = true; }),
    /is unreadable or invalid/,
  );
  assert.equal(admitRan, false);
});

test('a stale lock in an unwritable directory fails invite and principal writes promptly instead of spinning', (t) => {
  if (process.getuid?.() === 0) {
    t.skip('root bypasses 0o500 directory write permission');
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'hn-stale-unwritable-'));
  const stale = new Date(Date.now() - 20_000);
  for (const name of ['invites.json.lock', 'principals.json.lock']) {
    const lp = join(dir, name);
    writeFileSync(lp, 'stale');
    utimesSync(lp, stale, stale);
  }
  chmodSync(dir, 0o500);
  try {
    const script = `
      import { join } from 'node:path';
      import { InviteStore, PrincipalStore } from './src/stores.ts';
      const dir = process.env.LOCK_TEST_DIR;
      let invCode = '';
      try {
        new InviteStore(join(dir, 'invites.json')).mint({ scopes: ['worlds:join'] });
      } catch (e) {
        invCode = String(e?.code ?? e?.message ?? e);
      }
      let prinCode = '';
      try {
        new PrincipalStore(join(dir, 'principals.json')).add({ sub: 'agent:x@guest', name: 'X', kind: 'agent', key: null, scopes: [] });
      } catch (e) {
        prinCode = String(e?.code ?? e?.message ?? e);
      }
      console.log(JSON.stringify({ invCode, prinCode }));
    `;
    const r = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: ROOT,
      encoding: 'utf8',
      env: { ...process.env, LOCK_TEST_DIR: dir },
      timeout: 4_000,
    });
    assert.equal(r.error, undefined, `write hung past deadline: ${r.error?.message ?? r.signal}`);
    assert.equal(r.status, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim()) as { invCode: string; prinCode: string };
    assert.equal(out.invCode, 'EACCES');
    assert.equal(out.prinCode, 'EACCES');
  } finally {
    chmodSync(dir, 0o700);
  }
});
