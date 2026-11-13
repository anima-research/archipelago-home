import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKey } from '../src/keys.js';
import { verifyToken } from '../src/token.js';
import { makeEnrollRequest, makeTokenRequest } from '../src/statements.js';
import { handleEnroll, handleTokenRequest, type ExchangeDeps } from '../src/exchange.js';
import { InviteStore, MintLog, PrincipalStore } from '../src/stores.js';

const issuer = generateKey();
const agentKey = generateKey();
const ISS = 'id.test';

let deps: ExchangeDeps;
let principals: PrincipalStore;
let invites: InviteStore;
let testDir: string;

beforeEach(() => {
  const dir = mkdtempSync(join(tmpdir(), 'hn-test-'));
  writeFileSync(
    join(dir, 'principals.json'),
    JSON.stringify({
      principals: [
        {
          sub: 'agent:fable@animalabs.ai',
          name: 'Fable',
          kind: 'agent',
          key: agentKey.id,
          scopes: ['worlds:join'],
          tokenTtl: '14d',
        },
      ],
    }),
  );
  principals = new PrincipalStore(join(dir, 'principals.json'));
  invites = new InviteStore(join(dir, 'invites.json'));
  testDir = dir;
  deps = {
    issuer,
    iss: ISS,
    principals,
    invites,
    mintLog: new MintLog(join(dir, 'minted.jsonl')),
    knownAudiences: () => ['eidoverse'],
  };
});

test('key-proof exchange mints a verifiable token', () => {
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse');
  const res = handleTokenRequest(req, deps);
  assert.equal(res.status, 200);
  const v = verifyToken((res.body as { token: string }).token, { issuerId: issuer.id, iss: ISS, aud: 'eidoverse' });
  assert.ok(v.ok);
  assert.equal(v.payload.sub, 'agent:fable@animalabs.ai');
});

test('unenrolled key is refused', () => {
  const stranger = generateKey();
  const req = makeTokenRequest(stranger.privateKey, stranger.id, ISS, 'eidoverse');
  assert.equal(handleTokenRequest(req, deps).status, 403);
});

test('proof from wrong key is refused', () => {
  const stranger = generateKey();
  const req = { ...makeTokenRequest(stranger.privateKey, agentKey.id, ISS, 'eidoverse') };
  assert.equal(handleTokenRequest(req, deps).status, 403);
});

test('stale timestamp is refused', () => {
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse');
  req.timestamp = new Date(Date.now() - 10 * 60_000).toISOString();
  assert.equal(handleTokenRequest(req, deps).status, 400);
});

test('unknown audience is refused', () => {
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'nether');
  assert.equal(handleTokenRequest(req, deps).status, 400);
});

test('revoked principal is refused', () => {
  principals.revoke('agent:fable@animalabs.ai');
  const req = makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse');
  assert.equal(handleTokenRequest(req, deps).status, 403);
});

test('enroll: invite + key → new principal + token; invite consumed', () => {
  invites.mint({ code: 'inv_x', scopes: ['worlds:join'], maxUses: 1 });
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_x', 'Ferro');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 200);
  const body = res.body as { sub: string; token: string };
  assert.equal(body.sub, 'agent:ferro@guest');
  assert.ok(verifyToken(body.token, { issuerId: issuer.id, iss: ISS, aud: 'eidoverse' }).ok);
  assert.ok(principals.byKey(guest.id));
  // second use exhausts
  const guest2 = generateKey();
  const req2 = makeEnrollRequest(guest2.privateKey, guest2.id, ISS, 'inv_x', 'Bolt');
  assert.equal(handleEnroll(req2, deps).status, 403);
});


test('domain-bearing invite anchors the principal at the home domain', () => {
  invites.mint({ code: 'inv_home', scopes: ['worlds:join'], domain: 'animalabs.ai' });
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_home', 'Mythos');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 200);
  assert.equal((res.body as { sub: string }).sub, 'agent:mythos@animalabs.ai');
});

test('enroll: name collision refused (case-insensitive)', () => {
  invites.mint({ code: 'inv_y', scopes: ['worlds:join'] });
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_y', 'fable');
  const res = handleEnroll(req, deps);
  assert.equal(res.status, 403);
  assert.match((res.body as { error: string }).error, /name taken/);
});

test('enroll: bad invite refused', () => {
  const guest = generateKey();
  const req = makeEnrollRequest(guest.privateKey, guest.id, ISS, 'nope', 'Ferro');
  assert.equal(handleEnroll(req, deps).status, 403);
});

test('a requested ttl shortens the token and is reported as exp', () => {
  const req = { ...makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse'), ttl: '15m' };
  const res = handleTokenRequest(req, deps);
  assert.equal(res.status, 200);
  const body = res.body as { token: string; exp: number };
  const v = verifyToken(body.token, { issuerId: issuer.id, iss: ISS, aud: 'eidoverse' });
  assert.ok(v.ok);
  assert.equal(v.payload.exp, body.exp);
  const left = v.payload.exp - Math.floor(Date.now() / 1000);
  assert.ok(left > 14 * 60 && left <= 15 * 60, `about 15 minutes left, got ${left}s`);
});

test('a requested ttl cannot exceed the principal ceiling', () => {
  const req = { ...makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse'), ttl: '90d' };
  const res = handleTokenRequest(req, deps);
  assert.equal(res.status, 200);
  const left = (res.body as { exp: number }).exp - Math.floor(Date.now() / 1000);
  assert.ok(left <= 14 * 86400 && left > 13 * 86400, 'capped at the principal tokenTtl (14d)');
});

test('a malformed ttl is refused before the proof is checked', () => {
  const req = { ...makeTokenRequest(agentKey.privateKey, agentKey.id, ISS, 'eidoverse'), ttl: 'forever' };
  const res = handleTokenRequest(req, deps);
  assert.equal(res.status, 400);
});

test('enroll: while invites.json can’t be read, nothing is written — no principal left behind an unspent invite', () => {
  invites.mint({ code: 'inv_y', scopes: ['worlds:join'], maxUses: 1 });
  const path = join(testDir, 'invites.json');
  writeFileSync(path, '{ not json');
  utimesSync(path, new Date(), new Date(Date.now() + 5000));
  const guest = generateKey();
  const res = handleEnroll(makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_y', 'Wren'), deps);
  assert.equal(res.status, 503);
  assert.equal(principals.byKey(guest.id), undefined);
  assert.equal(readFileSync(path, 'utf8'), '{ not json'); // the damaged file, untouched
});

test('enroll: while principals.json can’t be read, a valid invite stays unspent and nothing is written', () => {
  invites.mint({ code: 'inv_z', scopes: ['worlds:join'], maxUses: 1 });
  const path = join(testDir, 'principals.json');
  writeFileSync(path, '{ not json');
  utimesSync(path, new Date(), new Date(Date.now() + 5000));
  const guest = generateKey();
  assert.equal(handleEnroll(makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_z', 'Moss'), deps).status, 503);
  assert.equal(typeof invites.check('inv_z', Date.now()), 'object'); // still claimable
  assert.equal(readFileSync(path, 'utf8'), '{ not json');
});

test('enroll: with no audience to mint for, it refuses before writing anything', () => {
  invites.mint({ code: 'inv_n', scopes: ['worlds:join'], maxUses: 1 });
  const guest = generateKey();
  const res = handleEnroll(makeEnrollRequest(guest.privateKey, guest.id, ISS, 'inv_n', 'Nook'), { ...deps, knownAudiences: () => [] });
  assert.equal(res.status, 400);
  assert.match(String((res.body as { error: string }).error), /no audience configured/);
  assert.equal(principals.byKey(guest.id), undefined);
  assert.equal(typeof invites.check('inv_n', Date.now()), 'object');
});

test('enroll: an invite whose token lifetime is unusable (unparseable, zero) refuses before writing anything', () => {
  for (const [code, ttl] of [['inv_t', 'forever'], ['inv_0', '0m']] as const) {
    invites.mint({ code, scopes: ['worlds:join'], maxUses: 1, tokenTtl: ttl });
    const guest = generateKey();
    const res = handleEnroll(makeEnrollRequest(guest.privateKey, guest.id, ISS, code, `Tern ${code}`), deps);
    assert.equal(res.status, 400, ttl);
    assert.match(String((res.body as { error: string }).error), /bad token lifetime/);
    assert.equal(principals.byKey(guest.id), undefined);
    assert.equal(typeof invites.check(code, Date.now()), 'object');
  }
});
